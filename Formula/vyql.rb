class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.3.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.3.0/vyql_v0.3.0_darwin_arm64.tar.gz"
      sha256 "139834037a46a20eaaf6f4af5ebcd8fac9eafe94ae343fcff955ba4c8e03c758"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.3.0/vyql_v0.3.0_darwin_amd64.tar.gz"
      sha256 "25c58087fcb22c22a22f75fdf3a3a6014b0870c94f492f7458c1eecc47f5fce7"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.3.0/vyql_v0.3.0_linux_arm64.tar.gz"
      sha256 "681266c22f250e1349600e2a048ecb7cc0388f702b2c5d8a168a696fedcfe6bc"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.3.0/vyql_v0.3.0_linux_amd64.tar.gz"
      sha256 "f06764452a5f0af67e6126b3adf74e41b651b04f109d0660a495b88e5ba0fbbf"
    end
  end

  # The scanner reads its security knowledge from a `vyql/` directory at run
  # time, and finds it by walking up from the resolved path of its own
  # executable. Keeping the binary and that directory together under libexec
  # preserves the relationship; `bin/vyql` is a symlink into it, which resolves
  # back to libexec before the search starts.
  def install
    libexec.install Dir["*"]
    bin.install_symlink libexec/"bin/vyql"
  end

  test do
    assert_match "vyql v#{version}", shell_output("#{bin}/vyql version")

    # Run from a directory with no `vyql/` above it, so the data can only be
    # found by resolving the symlink in bin. This is the failure mode that
    # makes a packaged install panic rather than scan.
    (testpath/"app.py").write <<~PYTHON
      import sqlite3

      def handler(req):
          cur = sqlite3.connect("app.db").cursor()
          cur.execute("SELECT * FROM t WHERE a = '" + req.args.get("a") + "'")
    PYTHON

    # A met -fail-on threshold exits 3: the check ran and did not pass. 1 means
    # vyql could not run and 2 means the invocation was wrong, so a packaging
    # fault cannot be mistaken here for the finding this fixture plants.
    output = shell_output("#{bin}/vyql scan #{testpath}", 3)
    assert_match "finding(s)", output

    # The same scan with the gate off exits 0.
    system bin/"vyql", "scan", "-fail-on", "none", testpath
  end
end
