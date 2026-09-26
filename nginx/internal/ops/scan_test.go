package ops

import "testing"

func TestCompiledConfigFrom(t *testing.T) {
	for _, c := range []struct{ v, want string }{
		{"nginx version: nginx/1.26.3\nconfigure arguments: --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --with-http_ssl_module", "/etc/nginx/nginx.conf"},
		{"configure arguments: --prefix=/usr/local/nginx --with-http_ssl_module", "/usr/local/nginx/conf/nginx.conf"},
		{"configure arguments: --prefix=/opt/web --conf-path=etc/web.conf", "/opt/web/etc/web.conf"},
		{"configure arguments: --with-http_ssl_module", "/usr/local/nginx/conf/nginx.conf"},
	} {
		if got := compiledConfigFrom(c.v); got != c.want {
			t.Errorf("compiledConfigFrom(%q) = %q, want %q", c.v, got, c.want)
		}
	}
}
