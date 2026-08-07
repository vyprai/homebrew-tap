class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.2.4"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.4/vyql_v0.2.4_darwin_arm64.tar.gz"
      sha256 "0ad92a14564752b4999f5404af55da641e39dd7f81c4c972292105046366fbc7"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.4/vyql_v0.2.4_darwin_amd64.tar.gz"
      sha256 "71d92386b1cf284b15b4eb560c65966e3d36454e292b12bf9df699fedb063137"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.4/vyql_v0.2.4_linux_arm64.tar.gz"
      sha256 "407092efcea31778bebd92ce1d8fec02214fd39b7deb215a2efcb2e33cf789ff"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.4/vyql_v0.2.4_linux_amd64.tar.gz"
      sha256 "565204e00bd8e4c3411fc23cb5a355d56e6024ecb4afd6a03a14649fae2d10ed"
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
