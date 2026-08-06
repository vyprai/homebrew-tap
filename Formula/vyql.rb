class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.2.3"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.3/vyql_v0.2.3_darwin_arm64.tar.gz"
      sha256 "e2b03b682d1aae94df6a36f00eb63df1986325af46d09f85efde8dde714486a5"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.3/vyql_v0.2.3_darwin_amd64.tar.gz"
      sha256 "547483cd808636ac3efd65cc0f9b0018e3ce4e64fb315e87b364b2f8644a9f4f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.3/vyql_v0.2.3_linux_arm64.tar.gz"
      sha256 "513d25caa4209f8586efd450b2e028b88e97a884875d358210fd20637b945bdb"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.3/vyql_v0.2.3_linux_amd64.tar.gz"
      sha256 "62c250e5504610a0ea8512e8822c74f92efb72dfa6dd1205526df1408de74344"
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

    output = shell_output("#{bin}/vyql scan #{testpath}", 1)
    assert_match "finding(s)", output

    # Findings at or above HIGH exit 1; the same scan gated off exits 0.
    system bin/"vyql", "scan", "--fail-on", "none", testpath
  end
end
