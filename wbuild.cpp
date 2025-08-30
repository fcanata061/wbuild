// wbuild.cpp — A single-file, C++17, source-based builder for Linux
// Author: You + ChatGPT
// License: MIT
//
// Overview
// --------
// wbuild is a lightweight, Linux-from-scratch–friendly source package builder.
// It manages "recipes" that define how to fetch, unpack, patch, build, and
// install software (via DESTDIR + fakeroot). It can also install prebuilt
// binary packages produced by wbuild, keep logs, support colored output and a
// spinner, perform sha256 integrity checks, provide simple reverse dependency
// scanning, and sync recipe repos via git.
//
// Key features implemented
// - Fetch sources via curl or git
// - Store downloads in a cache dir and unpack to a working dir (supports many
//   formats by invoking system tools: bsdtar/tar, unzip, xz, zstd, 7z)
// - Apply patches from: https/https, git (via `git apply`), or local filesystem
// - Build with recipe phases: preconfig, configure, build, postbuild
// - Package via DESTDIR, then optionally strip, then create a binary package
//   (.wbpkg = tar.zst by default) and install it system-wide with fakeroot
// - Install directly from a binary package too
// - Keep a local DB of installed packages + files for uninstall/rollback
// - colorized CLI, spinner, and structured logs per run
// - commands have abbreviations (e.g., `ins` for `install`)
// - `info`, `search`, `list`, `logs`, `undo` (rollback last install),
//   `remove`, post-remove hooks
// - `sha256` verification for downloads (uses sha256sum when present)
// - `sync` to commit & push your recipe git repo
// - `revdep` scan: finds broken shared-library links and suggests rebuilds
//
// Build
// -----
// Requires: g++ (C++17), linux, and common builder tools: curl, git, bsdtar or
// tar/unzip/xz/zstd/7z, patch, fakeroot, sha256sum, strip, file, ldd, find.
//
//   g++ -std=gnu++17 -O2 -pthread -o wbuild wbuild.cpp
//
// Suggested directories (auto-created if missing):
//   Root (prefix):         ~/.wbuild
//   DB:                    ~/.wbuild/db
//   Logs:                  ~/.wbuild/logs
//   Cache (downloads):     ~/.wbuild/cache
//   Work (build trees):    ~/.wbuild/work
//   Packages (bin pkgs):   ~/.wbuild/pkgs
//   Recipes:               ~/wbuild-recipes   (customizable via --recipes)
//   Hooks dir:             ~/.wbuild/hooks (e.g., post-remove scripts)
//
// Recipe format (.wbrc files)
// ---------------------------
// Very simple INI-like key=value, with comma-separated lists. Example:
//
//   name=hello
//   version=2.12
//   source=https://ftp.gnu.org/gnu/hello/hello-2.12.tar.gz
//   sha256=31e066137a962676... (optional)
//   patches=https://example/hello-fix.patch,git:my/patch/topic,./local.patch
//   workdir=hello-2.12
//   preconfig=autoreconf -fi
//   configure=./configure --prefix=/usr
//   build=make -j$(nproc)
//   postbuild=make check || true
//   strip=yes  # default from CLI if --strip is provided; can override here
//
// Save as: ~/wbuild-recipes/hello/hello-2.12.wbrc
// You can also omit version in filename; wbuild reads inside the file.
//
// CLI
// ---
//   wbuild help
//   wbuild fetch <recipe>
//   wbuild build <recipe> [--strip] [--destdir DIR] [--variant NAME]
//   wbuild install <recipe> [--strip] [--destdir DIR]
//   wbuild install-bin <pkg.wbpkg>
//   wbuild remove <name>
//   wbuild undo            # undo last install action
//   wbuild info <name>
//   wbuild search <query>
//   wbuild list
//   wbuild logs [--tail N]
//   wbuild sync [--repo PATH] [--message MSG]
//   wbuild revdep [--prefix /usr]
//   wbuild verify <recipe> # just verify sha256 of sources
//
// Abbreviations are accepted: ins, rm, ls, i, bld, fch, ib, inf, srch, lgs, sy, rd
//
// Notes
// -----
// - This is a pragmatic single-file implementation: robust enough to use,
//   but not a full distro-grade package manager. It favors calling proven
//   system tools and keeping logic simple and auditable.
// - Run as a user; installation uses fakeroot. To install system-wide under /
//   without fakeroot, run with appropriate privileges (at your own risk).

#include <bits/stdc++.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <filesystem>
#include <thread>
#include <atomic>
#include <chrono>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

// ----------------------- Utility: Colors & Spinner ------------------------
namespace ui {
    static const std::string reset = "\033[0m";
    static const std::string bold = "\033[1m";
    static const std::string dim = "\033[2m";
    static const std::string red = "\033[31m";
    static const std::string green = "\033[32m";
    static const std::string yellow = "\033[33m";
    static const std::string blue = "\033[34m";
    static const std::string magenta = "\033[35m";
    static const std::string cyan = "\033[36m";

    struct Spinner {
        std::atomic<bool> running{false};
        std::thread th;
        std::string prefix;
        Spinner(const std::string &pfx = "") : prefix(pfx) {}
        void start() {
            running = true;
            th = std::thread([this]{
                const char frames[] = "|/-\\";
                size_t i=0;
                while (running) {
                    std::cerr << "\r" << prefix << frames[i++ % 4] << "  " << std::flush;
                    std::this_thread::sleep_for(100ms);
                }
                std::cerr << "\r" << std::string(prefix.size()+4,' ') << "\r"; // clear
            });
        }
        void stop_ok(const std::string &msg="done"){
            running=false; if(th.joinable()) th.join();
            std::cerr << ui::green << "✔ " << ui::reset << msg << "\n";
        }
        void stop_fail(const std::string &msg="fail"){
            running=false; if(th.joinable()) th.join();
            std::cerr << ui::red << "✖ " << ui::reset << msg << "\n";
        }
        ~Spinner(){ if(running){ running=false; if(th.joinable()) th.join(); } }
    };
}

// --------------------------- Utility: Logging -----------------------------
struct Logger {
    fs::path logdir;
    fs::path logfile;
    std::ofstream ofs;
    std::mutex m;
    Logger(const fs::path &dir){
        logdir = dir; fs::create_directories(dir);
        auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::ostringstream name;
        name << std::put_time(std::localtime(&t), "%Y%m%d-%H%M%S") << ".log";
        logfile = logdir / name.str();
        ofs.open(logfile);
    }
    void log(const std::string &s){ std::lock_guard<std::mutex> g(m); ofs << s << "\n"; ofs.flush(); }
};

static std::unique_ptr<Logger> g_logger;
#define LOG(x) do { if(g_logger) g_logger->log(x); } while(0)

// -------------------------- Config / Paths --------------------------------
struct Paths {
    fs::path root;
    fs::path db, logs, cache, work, pkgs, hooks, recipes;
    Paths(){
        const char* home = getenv("HOME");
        root = home ? fs::path(home)/".wbuild" : fs::path(".wbuild");
        db = root/"db"; logs=root/"logs"; cache=root/"cache"; work=root/"work"; pkgs=root/"pkgs"; hooks=root/"hooks";
        recipes = fs::path(getenv("HOME")?getenv("HOME"):".")/"wbuild-recipes";
        fs::create_directories(db); fs::create_directories(logs); fs::create_directories(cache);
        fs::create_directories(work); fs::create_directories(pkgs); fs::create_directories(hooks);
        fs::create_directories(recipes);
    }
};

static Paths g_paths;

// --------------------------- Shell helpers --------------------------------
bool has_exec(const std::string &name){
    std::string path = getenv("PATH")?getenv("PATH"):"";
    std::stringstream ss(path); std::string dir;
    while(std::getline(ss, dir, ':')){
        fs::path p = fs::path(dir)/name;
        if(fs::exists(p) && access(p.c_str(), X_OK)==0) return true;
    }
    return false;
}

int run_cmd(const std::string &cmd, const fs::path &cwd = "."){
    LOG("RUN [" + cwd.string() + "]: " + cmd);
    std::string full = "bash -lc 'set -eo pipefail; " + cmd + "'";
    int rc=0;
    if(!cwd.empty()) rc = chdir(cwd.c_str());
    rc = system(full.c_str());
    return WIFEXITED(rc)? WEXITSTATUS(rc) : rc;
}

std::string run_capture(const std::string &cmd, const fs::path &cwd = "."){
    LOG("CAPTURE [" + cwd.string() + "]: " + cmd);
    std::string full = "bash -lc '" + cmd + "'";
    FILE *pipe = popen(full.c_str(), "r");
    if(!pipe) return "";
    std::string out; char buf[4096];
    while(fgets(buf, sizeof(buf), pipe)) out += buf;
    pclose(pipe);
    return out;
}

// ------------------------------ SHA256 ------------------------------------
bool sha256sum(const fs::path &file, std::string &out){
    if(!fs::exists(file)) return false;
    if(has_exec("sha256sum")){
        auto s = run_capture("sha256sum '"+file.string()+"' | awk '{print $1}'");
        if(!s.empty()){ out = s; out.erase(std::remove_if(out.begin(), out.end(), ::isspace), out.end()); return true; }
    }
    // Fallback: tiny builtin (not constant-time, but ok for integrity).
    // Minimal SHA256 implementation (public domain style) omitted for brevity.
    // For portability, require sha256sum; if missing, we warn.
    return false;
}

// ------------------------------ Download ----------------------------------
fs::path cache_download(const std::string &url){
    std::string fname = fs::path(url).filename().string();
    if(fname.empty()){
        // e.g., git URLs without filename; derive a safe name
        std::hash<std::string> h; fname = std::to_string(h(url));
    }
    fs::path out = g_paths.cache / fname;
    if(fs::exists(out)) return out;
    if(!has_exec("curl")) throw std::runtime_error("curl not found");
    ui::Spinner sp("downloading "); sp.start();
    int rc = run_cmd("curl -L --fail --retry 3 -o '"+out.string()+"' '"+url+"'");
    if(rc==0) { sp.stop_ok("downloaded " + out.filename().string()); return out; }
    sp.stop_fail("download failed");
    throw std::runtime_error("Failed to download: "+url);
}

// ------------------------------ Extract -----------------------------------
bool extract_with(const std::string &tool, const fs::path &archive, const fs::path &dest){
    fs::create_directories(dest);
    if(tool=="bsdtar"){
        return run_cmd("bsdtar -xpf '"+archive.string()+"' -C '"+dest.string()+"'")==0;
    } else if(tool=="tar"){
        return run_cmd("tar -xpf '"+archive.string()+"' -C '"+dest.string()+"'")==0;
    } else if(tool=="unzip"){
        return run_cmd("unzip -q '"+archive.string()+"' -d '"+dest.string()+"'")==0;
    } else if(tool=="7z"){
        return run_cmd("7z x -y -o'"+dest.string()+"' '"+archive.string()+"'")==0;
    }
    return false;
}

void extract_archive(const fs::path &archive, const fs::path &dest){
    ui::Spinner sp("extracting "); sp.start();
    std::vector<std::string> tools;
    if(has_exec("bsdtar")) tools.push_back("bsdtar");
    if(has_exec("tar")) tools.push_back("tar");
    if(has_exec("unzip")) tools.push_back("unzip");
    if(has_exec("7z")) tools.push_back("7z");
    for(auto &t: tools){ if(extract_with(t, archive, dest)){ sp.stop_ok("extracted"); return; } }
    sp.stop_fail("extract failed");
    throw std::runtime_error("No suitable extractor for " + archive.string());
}

// ------------------------------ Git helpers --------------------------------
void git_clone(const std::string &url, const fs::path &dest){
    if(!has_exec("git")) throw std::runtime_error("git not found");
    ui::Spinner sp("git clone "); sp.start();
    int rc = run_cmd("git clone --depth 1 '"+url+"' '"+dest.string()+"'");
    if(rc==0){ sp.stop_ok("cloned"); return; }
    sp.stop_fail("git clone failed");
    throw std::runtime_error("git clone failed: "+url);
}

void git_apply(const fs::path &repo_dir, const fs::path &patchfile){
    int rc = run_cmd("git apply --reject --whitespace=fix '"+patchfile.string()+"'", repo_dir);
    if(rc!=0) throw std::runtime_error("git apply failed for "+patchfile.string());
}

// ------------------------------ Recipe IO ----------------------------------
struct Recipe {
    std::string name, version;
    std::vector<std::string> sources; // URLs (http(s) or git: URL) or local paths
    std::vector<std::string> patches; // https/git/local
    std::string workdir; // subdir created after extract
    std::string preconfig, configure, build, postbuild;
    std::string sha256;
    std::optional<bool> strip;
};

static std::string trim(const std::string &s){
    auto a = s.find_first_not_of(" \t\r\n"); if(a==std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n"); return s.substr(a, b-a+1);
}

Recipe parse_recipe(const fs::path &file){
    Recipe r; std::ifstream ifs(file); if(!ifs) throw std::runtime_error("cannot open recipe "+file.string());
    std::string line; int ln=0;
    while(std::getline(ifs,line)){
        ln++;
        if(line.size()==0 || line[0]=='#') continue;
        auto eq = line.find('='); if(eq==std::string::npos) continue;
        std::string k = trim(line.substr(0,eq));
        std::string v = trim(line.substr(eq+1));
        auto split_list = [](const std::string &s){ std::vector<std::string> out; std::stringstream ss(s); std::string it; while(std::getline(ss,it,',')) out.push_back(trim(it)); return out; };
        if(k=="name") r.name=v; else if(k=="version") r.version=v;
        else if(k=="source"||k=="sources") r.sources = split_list(v);
        else if(k=="patches"||k=="patch") r.patches = split_list(v);
        else if(k=="workdir") r.workdir=v; else if(k=="preconfig") r.preconfig=v;
        else if(k=="configure") r.configure=v; else if(k=="build") r.build=v;
        else if(k=="postbuild"||k=="posbuild") r.postbuild=v; // accept both
        else if(k=="sha256") r.sha256=v; else if(k=="strip"){
            std::string lv = v; std::transform(lv.begin(), lv.end(), lv.begin(), ::tolower);
            r.strip = (lv=="1"||lv=="true"||lv=="yes"||lv=="on");
        }
    }
    if(r.name.empty()) throw std::runtime_error("recipe missing name");
    return r;
}

fs::path find_recipe_file(const std::string &name, const fs::path &recipes_dir){
    // find <name>*.wbrc in recipes_dir/<name>/ or directly
    fs::path p1 = recipes_dir / name;
    if(fs::exists(p1) && fs::is_directory(p1)){
        for(auto &e: fs::directory_iterator(p1)){
            if(e.is_regular_file() && e.path().extension()==".wbrc") return e.path();
        }
    }
    // fallback: search recursively for a matching file that starts with name
    for(auto &e: fs::recursive_directory_iterator(recipes_dir)){
        if(e.is_regular_file() && e.path().extension()==".wbrc"){
            std::string base = e.path().stem().string();
            if(base.rfind(name,0)==0) return e.path();
        }
    }
    throw std::runtime_error("recipe not found: "+name+" in "+recipes_dir.string());
}

// ------------------------------ Patch logic --------------------------------
fs::path fetch_patch(const std::string &spec){
    if(spec.rfind("http://",0)==0 || spec.rfind("https://",0)==0){
        return cache_download(spec);
    } else if(spec.rfind("git:",0)==0){
        // git:<repo_or_ref> — user supplies a repository URL or ref. We'll assume current src tree is a git repo and use `git fetch` then `git cherry-pick` is too heavy.
        // Simpler: we expect a local patch file reachable via git show.
        // Implement as: git -C <work> fetch <repo> && git -C <work> cherry-pick <ref>
        // Here we just return a dummy marker path encoding the spec; handled later.
        return fs::path("GIT:")+spec.substr(4);
    } else {
        fs::path p = fs::absolute(spec);
        if(!fs::exists(p)) throw std::runtime_error("patch not found: "+p.string());
        return p;
    }
}

void apply_patches(const std::vector<std::string> &patches, const fs::path &workdir){
    for(const auto &p: patches){
        auto fetched = fetch_patch(p);
        if(fetched.string().rfind("GIT:",0)==0){
            std::string ref = fetched.string().substr(4);
            // interpret as repo@ref or just ref for current origin
            auto at = ref.find('@');
            std::string repo = at==std::string::npos?"origin":ref.substr(0,at);
            std::string rref = at==std::string::npos?ref:ref.substr(at+1);
            int rc = run_cmd("git fetch '"+repo+"' '"+rref+"' && git cherry-pick FETCH_HEAD", workdir);
            if(rc!=0) throw std::runtime_error("git cherry-pick failed for "+ref);
            continue;
        }
        // Try git apply first if .git exists
        if(fs::exists(workdir/".git")){
            git_apply(workdir, fetched);
        } else {
            int rc = run_cmd("patch -p1 < '"+fetched.string()+"'", workdir);
            if(rc!=0) throw std::runtime_error("patch failed for "+fetched.string());
        }
    }
}

// --------------------------- Packaging DB ----------------------------------
struct PkgRecord{
    std::string name, version, variant;
    std::vector<std::string> files; // installed file paths
};

fs::path db_record_path(const std::string &name, const std::string &variant=""){
    std::string fname = name + (variant.empty()?"":"@"+variant) + ".txt";
    return g_paths.db / fname;
}

void db_save(const PkgRecord &r){
    fs::path f = db_record_path(r.name, r.variant);
    std::ofstream ofs(f);
    ofs << r.name << "\n" << r.version << "\n" << r.variant << "\n";
    for(auto &x: r.files) ofs << x << "\n";
}

bool db_load(const std::string &name, PkgRecord &out){
    // Load by any variant (prefer base). If multiple, first alpha.
    std::vector<fs::path> candidates;
    for(auto &e: fs::directory_iterator(g_paths.db)){
        if(e.is_regular_file()){
            auto bn = e.path().filename().string();
            if(bn.rfind(name,0)==0 && bn.find('.')!=std::string::npos) candidates.push_back(e.path());
        }
    }
    if(candidates.empty()) return false;
    std::sort(candidates.begin(), candidates.end());
    std::ifstream ifs(candidates[0]); if(!ifs) return false;
    std::getline(ifs, out.name); std::getline(ifs, out.version); std::getline(ifs, out.variant);
    std::string line; while(std::getline(ifs, line)) if(!line.empty()) out.files.push_back(line);
    return true;
}

void db_remove(const std::string &name){
    for(auto &e: fs::directory_iterator(g_paths.db)){
        auto bn = e.path().filename().string();
        if(bn.rfind(name,0)==0) fs::remove(e.path());
    }
}

// --------------------------- Build / Install -------------------------------
struct BuildOpts {
    bool strip=false;
    std::string destdir;
    std::string variant;
};

std::string expand_vars(const std::string &in, const Recipe &r, const BuildOpts &o){
    auto s = in;
    auto repl = [&](const std::string &k, const std::string &v){
        size_t pos=0; std::string needle = "${"+k+"}";
        while((pos=s.find(needle, pos))!=std::string::npos){ s.replace(pos, needle.size(), v); pos += v.size(); }
    };
    repl("name", r.name); repl("version", r.version); repl("destdir", o.destdir);
    repl("variant", o.variant);
    repl("jobs", std::to_string(std::thread::hardware_concurrency()));
    return s;
}

struct BuildContext{
    Recipe r; BuildOpts o;
    fs::path build_root; // ~/.wbuild/work/name-version[-variant]
    fs::path srcdir;     // build_root/workdir or first extracted dir
    fs::path destdir;    // build_root/dest
};

fs::path guess_top_subdir(const fs::path &dir){
    // If archive extracted a single dir, use it; otherwise, use dir itself
    size_t entries=0; fs::path only;
    for(auto &e: fs::directory_iterator(dir)){ entries++; if(entries==1) only=e.path(); }
    if(entries==1 && fs::is_directory(only)) return only; return dir;
}

fs::path package_path(const Recipe &r, const BuildOpts &o){
    std::string base = r.name + "-" + r.version + (o.variant.empty()?"":"-"+o.variant) + ".wbpkg";
    return g_paths.pkgs / base;
}

void do_fetch_extract(BuildContext &ctx){
    ui::Spinner sp("fetch+extract "); sp.start();
    // Create build root
    std::string br = ctx.r.name + "-" + ctx.r.version + (ctx.o.variant.empty()?"":"-"+ctx.o.variant);
    ctx.build_root = g_paths.work / br;
    fs::create_directories(ctx.build_root);
    // Download and extract all sources (first one considered primary)
    bool primary_set=false; fs::path primary_dir=ctx.build_root;
    for(const auto &src: ctx.r.sources){
        if(src.rfind("git://",0)==0 || src.rfind("git@",0)==0 || src.rfind("git+",0)==0 || src.rfind("ssh://",0)==0 || src.rfind("git:",0)==0){
            fs::path gdest = ctx.build_root / "git-src";
            git_clone(src.substr(src.find(':')!=std::string::npos?src.find(':')+1:0), gdest);
            if(!primary_set){ primary_dir=gdest; primary_set=true; }
            continue;
        }
        fs::path file = (src.rfind("http://",0)==0 || src.rfind("https://",0)==0) ? cache_download(src) : fs::path(src);
        if(!ctx.r.sha256.empty()){
            std::string got; if(sha256sum(file, got)){
                if(got!=ctx.r.sha256){ sp.stop_fail("sha256 mismatch"); throw std::runtime_error("sha256 mismatch for "+file.string()); }
            } else {
                std::cerr << ui::yellow << "warning:" << ui::reset << " sha256sum not available; skipping verification\n";
            }
        }
        fs::path exdir = ctx.build_root / (file.stem().string()+"-src");
        extract_archive(file, exdir);
        if(!primary_set){ primary_dir = guess_top_subdir(exdir); primary_set=true; }
    }
    ctx.srcdir = primary_dir;
    sp.stop_ok("sources ready");
}

void do_patch(BuildContext &ctx){
    if(ctx.r.patches.empty()) return;
    ui::Spinner sp("patching "); sp.start();
    apply_patches(ctx.r.patches, ctx.srcdir);
    sp.stop_ok("patched");
}

void do_build(BuildContext &ctx){
    ctx.destdir = ctx.build_root / "dest";
    fs::create_directories(ctx.destdir);
    auto phase = [&](const std::string &title, const std::string &cmd){
        if(cmd.empty()) return;
        std::string expanded = expand_vars(cmd, ctx.r, ctx.o);
        std::cerr << ui::cyan << title << ui::reset << ": " << expanded << "\n";
        int rc = run_cmd(expanded, ctx.srcdir);
        if(rc!=0) throw std::runtime_error(title+" failed");
    };
    // Export DESTDIR for phases
    std::string export_env = "export DESTDIR='"+ctx.destdir.string()+"'";
    if(!ctx.r.preconfig.empty()) phase("preconfig", export_env+" && "+ctx.r.preconfig);
    if(!ctx.r.configure.empty()) phase("configure", export_env+" && "+ctx.r.configure);
    if(!ctx.r.build.empty()) phase("build", export_env+" && "+ctx.r.build);
    if(!ctx.r.postbuild.empty()) phase("postbuild", export_env+" && "+ctx.r.postbuild);

    // If not installed yet, try conventional targets
    // Try: make DESTDIR=... install
    std::cerr << ui::cyan << "install (DESTDIR)" << ui::reset << "\n";
    int rc = run_cmd("make DESTDIR='"+ctx.destdir.string()+"' install || ninja install || cmake --install . --prefix /usr", ctx.srcdir);
    if(rc!=0) throw std::runtime_error("install phase failed");

    // Optional strip
    bool do_strip = ctx.o.strip; if(ctx.r.strip.has_value()) do_strip = *ctx.r.strip;
    if(do_strip){
        if(has_exec("strip")){
            run_cmd("find '"+ctx.destdir.string()+"' -type f -exec file {} + | grep ELF | cut -d: -f1 | xargs -r strip --strip-unneeded || true");
        }
    }
}

Pcg32 random_engine(){
    struct Pcg32 { std::mt19937_64 rng; unsigned operator()(){return (unsigned)rng();} };
    return Pcg32{std::mt19937_64(std::random_device{}())};
}

void do_package(BuildContext &ctx){
    fs::path pkg = package_path(ctx.r, ctx.o);
    if(fs::exists(pkg)) fs::remove(pkg);
    // Create tar.zst by default
    std::string cmd = "bash -lc 'cd " + (ctx.destdir.string()) + " && ";
    if(has_exec("tar")){
        if(has_exec("zstd")) cmd += "tar -cf - . | zstd -19 -T0 -o '"+pkg.string()+"'";
        else cmd += "tar -czf '"+pkg.string()+"' .";
    } else if(has_exec("bsdtar")){
        cmd += "bsdtar -acf '"+pkg.string()+"' .";
    } else {
        throw std::runtime_error("no tar available to create package");
    }
    cmd += "'"; // end bash -lc
    int rc = system(cmd.c_str());
    if(rc!=0) throw std::runtime_error("packaging failed");
    std::cerr << ui::green << "created package: " << ui::reset << pkg.string() << "\n";
}

std::vector<std::string> list_files_in_pkg(const fs::path &pkg){
    std::vector<std::string> files;
    if(pkg.extension()==".wbpkg"){ // our tar.* file
        std::string cmd;
        if(has_exec("tar")) cmd = "tar -tf '"+pkg.string()+"'";
        else if(has_exec("bsdtar")) cmd = "bsdtar -tf '"+pkg.string()+"'";
        else throw std::runtime_error("no tar to list pkg");
        auto out = run_capture(cmd);
        std::stringstream ss(out); std::string line; while(std::getline(ss,line)) if(!line.empty()) files.push_back("/"+line);
    }
    return files;
}

void do_install_bin(const fs::path &pkg, const std::string &name, const std::string &version, const std::string &variant){
    if(!has_exec("fakeroot")) std::cerr << ui::yellow << "warning:" << ui::reset << " fakeroot not found; attempting real install (may need root)\n";
    std::string cmd;
    if(has_exec("tar"))
        cmd = (has_exec("fakeroot")?"fakeroot -- ":"") + std::string("bash -lc \"tar -xpf '") + pkg.string() + "' -C /\"";
    else if(has_exec("bsdtar"))
        cmd = (has_exec("fakeroot")?"fakeroot -- ":"") + std::string("bash -lc \"bsdtar -xpf '") + pkg.string() + "' -C /\"";
    else throw std::runtime_error("no tar to install package");

    int rc = system(cmd.c_str());
    if(rc!=0) throw std::runtime_error("binary install failed");

    // Record files
    PkgRecord rec; rec.name=name; rec.version=version; rec.variant=variant;
    rec.files = list_files_in_pkg(pkg);
    db_save(rec);
}

// ------------------------------ Commands -----------------------------------
void cmd_help(){
    std::cout << ui::bold << "wbuild" << ui::reset << " — minimal source builder\n\n"
              << "Usage: wbuild <command> [args]\n\n"
              << "Commands:\n"
              << "  help\n  fetch <recipe>\n  build <recipe> [--strip] [--destdir DIR] [--variant NAME]\n"
              << "  install <recipe> [--strip] [--destdir DIR]\n  install-bin <pkg.wbpkg>\n  remove <name>\n  undo\n  info <name>\n  search <query>\n  list\n  logs [--tail N]\n  sync [--repo PATH] [--message MSG]\n  revdep [--prefix /usr]\n  verify <recipe>\n";
}

bool is_abbr(const std::string &cmd, const std::string &full){
    return full.rfind(cmd,0)==0; // cmd is a prefix of full
}

fs::path ensure_recipe(const std::string &name, const fs::path &over={}){
    fs::path dir = over.empty()?g_paths.recipes:over;
    return find_recipe_file(name, dir);
}

void command_fetch(const Recipe &r, BuildOpts o){
    BuildContext ctx{r,o}; do_fetch_extract(ctx); do_patch(ctx);
}

void command_build(const Recipe &r, BuildOpts o){
    BuildContext ctx{r,o}; do_fetch_extract(ctx); do_patch(ctx); do_build(ctx); do_package(ctx);
}

void command_install(const Recipe &r, BuildOpts o){
    BuildContext ctx{r,o}; do_fetch_extract(ctx); do_patch(ctx); do_build(ctx); do_package(ctx);
    fs::path pkg = package_path(r,o);
    do_install_bin(pkg, r.name, r.version, o.variant);
}

void command_install_bin(const fs::path &pkg){
    // Infer name-version from filename: name-version[-variant].wbpkg
    auto base = pkg.stem().string();
    std::string name, version, variant;
    // Split by '-' from the right; assume last token is version start when it looks like x.y
    auto pos = base.find('-'); if(pos==std::string::npos) throw std::runtime_error("bad package name");
    // naive parse
    std::stringstream ss(base); std::string tok; std::vector<std::string> t; while(std::getline(ss, tok, '-')) t.push_back(tok);
    if(t.size()<2) throw std::runtime_error("bad package name");
    name = t[0]; version = t[1]; if(t.size()>2){ variant = t[2]; }
    do_install_bin(pkg, name, version, variant);
}

void command_remove(const std::string &name){
    PkgRecord r; if(!db_load(name, r)) throw std::runtime_error("not installed: "+name);
    // Remove files (best-effort)
    for(auto it = r.files.rbegin(); it!=r.files.rend(); ++it){ fs::path p = *it; if(p!="/" && fs::exists(p)) fs::remove(p); }
    // Post-remove hooks
    fs::path pr = g_paths.hooks/"post-remove";
    if(fs::exists(pr) && fs::is_regular_file(pr)) run_cmd("bash '"+pr.string()+"' '"+name+"'");
    db_remove(name);
}

void command_undo(){
    // Undo last install: pick latest db record by mtime
    fs::path latest; std::time_t mt=0;
    for(auto &e: fs::directory_iterator(g_paths.db)){
        auto t = fs::last_write_time(e.path());
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(t - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
        auto tt = std::chrono::system_clock::to_time_t(sctp);
        if(tt>mt){ mt=tt; latest=e.path(); }
    }
    if(latest.empty()) throw std::runtime_error("nothing to undo");
    std::ifstream ifs(latest); PkgRecord r; std::getline(ifs,r.name); std::getline(ifs,r.version); std::getline(ifs,r.variant);
    std::string line; while(std::getline(ifs,line)) if(!line.empty()) r.files.push_back(line);
    for(auto it=r.files.rbegin(); it!=r.files.rend(); ++it){ fs::path p=*it; if(fs::exists(p)) fs::remove(p); }
    fs::remove(latest);
}

void command_info(const std::string &name){
    PkgRecord r; if(!db_load(name, r)) throw std::runtime_error("not installed: "+name);
    std::cout << ui::bold << r.name << ui::reset << " " << r.version; if(!r.variant.empty()) std::cout << " ("<<r.variant<<")"; std::cout << "\n";
    std::cout << r.files.size() << " files installed\n";
}

void command_search(const std::string &query){
    for(auto &e: fs::recursive_directory_iterator(g_paths.recipes)){
        if(e.is_regular_file() && e.path().extension()==".wbrc"){
            auto name = e.path().stem().string();
            if(name.find(query)!=std::string::npos){ std::cout << name << "\t" << e.path().string() << "\n"; }
        }
    }
}

void command_list(){
    for(auto &e: fs::directory_iterator(g_paths.db)){
        std::ifstream ifs(e.path()); std::string n,v,var; std::getline(ifs,n); std::getline(ifs,v); std::getline(ifs,var);
        std::cout << n << "\t" << v; if(!var.empty()) std::cout << "\t"<<var; std::cout << "\n";
    }
}

void command_logs(int tail){
    // show last N lines of latest log
    fs::path latest; std::time_t mt=0;
    for(auto &e: fs::directory_iterator(g_paths.logs)){
        auto t = fs::last_write_time(e.path());
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(t - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
        auto tt = std::chrono::system_clock::to_time_t(sctp);
        if(tt>mt){ mt=tt; latest=e.path(); }
    }
    if(latest.empty()){ std::cout << "no logs\n"; return; }
    std::ifstream ifs(latest); std::deque<std::string> q; std::string line;
    while(std::getline(ifs,line)){ q.push_back(line); if((int)q.size()>tail) q.pop_front(); }
    for(auto &l: q) std::cout << l << "\n";
}

void command_sync(const fs::path &repo, const std::string &msg){
    fs::path dir = repo.empty()?g_paths.recipes:repo;
    int rc = run_cmd("git add -A && git commit -m '"+msg+"' || true && git push", dir);
    if(rc!=0) throw std::runtime_error("sync failed");
}

void command_revdep(const std::string &prefix){
    // scan ELF in prefix/bin and lib for missing so dependencies
    std::vector<fs::path> bins;
    for(auto &p: {fs::path(prefix)/"bin", fs::path(prefix)/"sbin", fs::path(prefix)/"lib", fs::path(prefix)/"lib64"}){
        if(fs::exists(p)){
            for(auto &e: fs::recursive_directory_iterator(p)){
                if(e.is_regular_file()) bins.push_back(e.path());
            }
        }
    }
    std::set<std::string> broken;
    for(auto &b: bins){
        auto ft = run_capture("file -b '"+b.string()+"'");
        if(ft.find("ELF")!=std::string::npos){
            auto l = run_capture("ldd '"+b.string()+"' 2>&1");
            if(l.find("not found")!=std::string::npos){ broken.insert(b.string()); }
        }
    }
    if(broken.empty()){ std::cout << "No broken links found.\n"; return; }
    std::cout << ui::yellow << "Broken dependencies in:" << ui::reset << "\n";
    for(auto &x: broken) std::cout << "  " << x << "\n";
    std::cout << "Suggested actions: rebuild packages providing missing .so; run: wbuild search <libname> then reinstall.\n";
}

void command_verify(const Recipe &r, BuildOpts){
    for(const auto &src: r.sources){
        if(r.sha256.empty()){ std::cout << "no sha256 in recipe\n"; return; }
        fs::path file = (src.rfind("http://",0)==0 || src.rfind("https://",0)==0) ? cache_download(src) : fs::path(src);
        std::string got; if(!sha256sum(file, got)) throw std::runtime_error("sha256sum tool not found");
        if(got==r.sha256) std::cout << ui::green << "OK" << ui::reset << " " << file.filename().string() << "\n";
        else { std::cout << ui::red << "MISMATCH" << ui::reset << " for " << file << "\n"; }
    }
}

// ------------------------------ Main ---------------------------------------
int main(int argc, char** argv){
    // Initialize logger
    g_logger = std::make_unique<Logger>(g_paths.logs);
    LOG("wbuild start");

    std::vector<std::string> args(argv+1, argv+argc);
    if(args.empty()){ cmd_help(); return 0; }

    auto pop = [&](const std::string &flag)->std::optional<std::string>{
        for(size_t i=0;i<args.size();++i){ if(args[i]==flag && i+1<args.size()){ auto v=args[i+1]; args.erase(args.begin()+i, args.begin()+i+2); return v; } }
        return std::nullopt;
    };
    auto has = [&](const std::string &flag){ return std::find(args.begin(), args.end(), flag)!=args.end(); };

    // Global options
    auto recipes_dir_opt = pop("--recipes"); if(recipes_dir_opt) g_paths.recipes = *recipes_dir_opt;

    std::string cmd = args[0];

    try{
        if(cmd=="help" || is_abbr(cmd,"help")){
            cmd_help(); return 0;
        }
        else if(cmd=="fetch" || is_abbr(cmd,"fetch") || is_abbr(cmd,"fch")){
            if(args.size()<2) throw std::runtime_error("usage: wbuild fetch <recipe>");
            auto rf = ensure_recipe(args[1]); auto r = parse_recipe(rf); BuildOpts o; command_fetch(r,o);
        }
        else if(cmd=="build" || is_abbr(cmd,"build") || cmd=="bld"){
            if(args.size()<2) throw std::runtime_error("usage: wbuild build <recipe>");
            BuildOpts o; o.strip = has("--strip"); if(auto d=pop("--destdir")) o.destdir=*d; if(auto v=pop("--variant")) o.variant=*v;
            auto rf = ensure_recipe(args[1]); auto r = parse_recipe(rf); command_build(r,o);
        }
        else if(cmd=="install" || cmd=="ins" || is_abbr(cmd,"install") || cmd=="i"){
            if(args.size()<2) throw std::runtime_error("usage: wbuild install <recipe>");
            BuildOpts o; o.strip = has("--strip"); if(auto d=pop("--destdir")) o.destdir=*d;
            auto rf = ensure_recipe(args[1]); auto r = parse_recipe(rf); command_install(r,o);
        }
        else if(cmd=="install-bin" || cmd=="ib"){
            if(args.size()<2) throw std::runtime_error("usage: wbuild install-bin <pkg.wbpkg>");
            command_install_bin(args[1]);
        }
        else if(cmd=="remove" || cmd=="rm"){
            if(args.size()<2) throw std::runtime_error("usage: wbuild remove <name>");
            command_remove(args[1]);
        }
        else if(cmd=="undo"){
            command_undo();
        }
        else if(cmd=="info" || cmd=="inf"){
            if(args.size()<2) throw std::runtime_error("usage: wbuild info <name>");
            command_info(args[1]);
        }
        else if(cmd=="search" || cmd=="srch"){
            if(args.size()<2) throw std::runtime_error("usage: wbuild search <query>");
            command_search(args[1]);
        }
        else if(cmd=="list" || cmd=="ls"){
            command_list();
        }
        else if(cmd=="logs" || cmd=="lgs"){
            int tail = 200; if(auto t=pop("--tail")) tail = std::stoi(*t); command_logs(tail);
        }
        else if(cmd=="sync" || cmd=="sy"){
            fs::path repo; if(auto r=pop("--repo")) repo=*r; std::string msg = pop("--message").value_or("wbuild sync");
            command_sync(repo,msg);
        }
        else if(cmd=="revdep" || cmd=="rd"){
            std::string prefix = pop("--prefix").value_or("/usr"); command_revdep(prefix);
        }
        else if(cmd=="verify"){
            if(args.size()<2) throw std::runtime_error("usage: wbuild verify <recipe>");
            auto rf = ensure_recipe(args[1]); auto r = parse_recipe(rf); BuildOpts o; command_verify(r,o);
        }
        else {
            throw std::runtime_error("unknown command: "+cmd);
        }
        return 0;
    } catch(const std::exception &e){
        std::cerr << ui::red << "error: " << ui::reset << e.what() << "\n";
        LOG(std::string("ERR ")+e.what());
        return 1;
    }
}
