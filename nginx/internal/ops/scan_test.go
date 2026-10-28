package ops

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBuildFrom(t *testing.T) {
	for _, c := range []struct{ v, conf, pid string }{
		{"nginx version: nginx/1.26.3\nconfigure arguments: --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --pid-path=/run/nginx.pid --with-http_ssl_module",
			"/etc/nginx/nginx.conf", "/run/nginx.pid"},
		{"configure arguments: --prefix=/usr/local/nginx --with-http_ssl_module", "/usr/local/nginx/conf/nginx.conf", "/usr/local/nginx/logs/nginx.pid"},
		{"configure arguments: --prefix=/opt/web --conf-path=etc/web.conf", "/opt/web/etc/web.conf", "/opt/web/logs/nginx.pid"},
		{"configure arguments: --with-http_ssl_module", "/usr/local/nginx/conf/nginx.conf", "/usr/local/nginx/logs/nginx.pid"},
	} {
		b := buildFrom(c.v)
		if got := under(b.prefix, b.conf); got != c.conf {
			t.Errorf("%q: configuration %q, want %q", c.v, got, c.conf)
		}
		if got := under(b.prefix, b.pid); got != c.pid {
			t.Errorf("%q: pid file %q, want %q", c.v, got, c.pid)
		}
	}
}

// The flags come back out of the title nginx gives its master, where the
// arguments were joined by spaces.
func TestStartupOf(t *testing.T) {
	for title, want := range map[string]startup{
		"nginx: master process /usr/sbin/nginx -g daemon on; master_process on;": {globals: "daemon on; master_process on;"},
		"nginx: master process nginx -g daemon off;":                             {globals: "daemon off;"},
		"nginx: master process /usr/sbin/nginx -c /etc/nginx-second/nginx.conf":  {config: "/etc/nginx-second/nginx.conf"},
		"nginx: master process /opt/n/sbin/nginx -p /srv/site -c conf/a.conf -g pid /run/a.pid; worker_processes 2;": {
			prefix: "/srv/site", config: "conf/a.conf", globals: "pid /run/a.pid; worker_processes 2;"},
		"nginx: master process nginx -c/etc/x.conf -p/srv": {config: "/etc/x.conf", prefix: "/srv"},
		"nginx: master process /usr/sbin/nginx":            {},
	} {
		if got := startupOf(title); got != want {
			t.Errorf("%q: %+v, want %+v", title, got, want)
		}
	}
}

func TestReplayed(t *testing.T) {
	for in, want := range map[string]string{
		"daemon on; master_process on;":        "",
		"daemon off;":                          "",
		"pid /run/a.pid; daemon off;":          "pid /run/a.pid;",
		"worker_processes  2;error_log x.log;": "worker_processes 2; error_log x.log;",
		`error_log "/a;b";`:                    `error_log "/a;b";`,
		"":                                     "",
	} {
		if got := replayed(in); got != want {
			t.Errorf("replayed(%q) = %q, want %q", in, got, want)
		}
	}
}

// The test and signal commands repeat the flags that change which files
// nginx reads, and only those.
func TestCommandsRepeatTheStartupFlags(t *testing.T) {
	b := buildFrom("configure arguments: --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf")
	for _, c := range []struct {
		in   instance
		want string
	}{
		{instance{Exe: "/usr/sbin/nginx", Prefix: "/usr/share/nginx", ConfigPath: "/etc/nginx/nginx.conf"}, "/usr/sbin/nginx -s reload"},
		{instance{Exe: "/usr/sbin/nginx", Prefix: "/usr/share/nginx", ConfigPath: "/etc/nginx-second/nginx.conf"},
			"/usr/sbin/nginx -c /etc/nginx-second/nginx.conf -s reload"},
		{instance{Exe: "/usr/sbin/nginx", Prefix: "/srv/site", PrefixGiven: true, ConfigPath: "/etc/nginx/nginx.conf", Globals: "pid /run/a.pid;"},
			"/usr/sbin/nginx -p /srv/site -g 'pid /run/a.pid;' -s reload"},
	} {
		c.in.build = b
		if got := c.in.command("-s", "reload"); got != c.want {
			t.Errorf("%+v: %q, want %q", c.in, got, c.want)
		}
	}
}

// The pid file is the configuration's, else -g's, else the compiled one,
// under the master's prefix.
func TestPidFile(t *testing.T) {
	root := tree(t, map[string]string{
		"with.conf":    "pid run/with.pid;\nevents {}\n",
		"without.conf": "events {}\n",
	})
	b := buildFrom("configure arguments: --prefix=/usr/local/nginx")
	for _, c := range []struct {
		conf, globals, want string
	}{
		{"with.conf", "", "/srv/p/run/with.pid"},
		{"without.conf", "pid /run/g.pid;", "/run/g.pid"},
		{"without.conf", "", "/srv/p/logs/nginx.pid"},
	} {
		in := instance{Prefix: "/srv/p", ConfigPath: root + "/" + c.conf, Globals: c.globals, build: b}
		if got := in.pidFile(); got != c.want {
			t.Errorf("%s -g %q: %q, want %q", c.conf, c.globals, got, c.want)
		}
	}
}

// The guard passes only while the pid file names the master and the master
// runs the binary it ran.
func TestGuard(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	root := tree(t, map[string]string{"nginx.conf": "pid /ROOT/nginx.pid;\nevents {}\n"})
	conf := root + "/nginx.conf"
	if err := writeFile(conf, strings.ReplaceAll(content(t, conf), "/ROOT", root)); err != nil {
		t.Fatal(err)
	}
	self := os.Getpid()
	in := instance{PID: self, Exe: exeOf(self), Prefix: root, ConfigPath: conf, build: buildFrom("")}
	if err := in.guard(); err == nil {
		t.Fatal("no pid file, guard passed")
	}
	if err := writeFile(root+"/nginx.pid", strconv.Itoa(self)+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := in.guard(); err != nil {
		t.Fatalf("pid file names the master: %v", err)
	}
	if err := writeFile(root+"/nginx.pid", "1\n"); err != nil {
		t.Fatal(err)
	}
	if err := in.guard(); err == nil {
		t.Fatal("pid file names pid 1, guard passed")
	}
	in.Exe = "/usr/sbin/nginx"
	if err := writeFile(root+"/nginx.pid", strconv.Itoa(self)+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := in.guard(); err == nil {
		t.Fatal("another binary, guard passed")
	}
}

// Files of the configuration edited after it was loaded, including one a
// pattern include now matches, and not those left alone.
func TestChangedAfter(t *testing.T) {
	root := tree(t, map[string]string{
		"nginx.conf":    "events {}\nhttp { include /ROOT/conf.d/*.conf; }\n",
		"conf.d/a.conf": "server { listen 1443; }\n",
	})
	conf := root + "/nginx.conf"
	if err := writeFile(conf, strings.ReplaceAll(content(t, conf), "/ROOT", root)); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for _, f := range []string{conf, root + "/conf.d/a.conf"} {
		if err := os.Chtimes(f, old, old); err != nil {
			t.Fatal(err)
		}
	}
	loaded := time.Now().Add(-time.Minute)
	if got := changedAfter(conf, loaded); len(got) != 0 {
		t.Fatalf("nothing edited: %v", got)
	}
	if err := writeFile(root+"/conf.d/b.conf", "server { listen 2443; }\n"); err != nil {
		t.Fatal(err)
	}
	if got := changedAfter(conf, loaded); len(got) != 1 || got[0] != root+"/conf.d/b.conf" {
		t.Fatalf("a new included file: %v", got)
	}
	// Within the slack of the load, an edit is taken as part of it.
	if got := changedAfter(conf, time.Now()); len(got) != 0 {
		t.Fatalf("an edit as old as the load: %v", got)
	}
}
