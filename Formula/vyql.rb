class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.2.1"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.1/vyql_v0.2.1_darwin_arm64.tar.gz"
      sha256 "1fcb069aa1529f0370ea16b4045d5e95620922e140fa8dcf3e94b4ce8c7ac035"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.1/vyql_v0.2.1_darwin_amd64.tar.gz"
      sha256 "be0fbab51a3e6cdda7d11a67e9ef27e0642e4a568857e7c697413957821e9044"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.1/vyql_v0.2.1_linux_arm64.tar.gz"
      sha256 "1542ad13bd14d481a2a61765f2ebecf3e4ca6a773358b52bf1dc2d9ccdc0854d"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.1/vyql_v0.2.1_linux_amd64.tar.gz"
      sha256 "f4514a278646c1d721688a6a936ebe5ff5b0e7cf594fc68f271f6c910597bc67"
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
