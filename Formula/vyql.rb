class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.2.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.2/vyql_v0.2.2_darwin_arm64.tar.gz"
      sha256 "40614092292be0d450376e5c230125dcc6e6a92f82c6932d8c180b0d372ebba0"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.2/vyql_v0.2.2_darwin_amd64.tar.gz"
      sha256 "50408d56a8a6c22e1c749c5a0564035b83b3707cebc8211f10506df3dc90d06b"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.2/vyql_v0.2.2_linux_arm64.tar.gz"
      sha256 "155083c81a317cfca6731d6a4537fefb5a30350139e2b8c1816e809e5a20d211"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.2/vyql_v0.2.2_linux_amd64.tar.gz"
      sha256 "6313286a6c3b540fb957e1204db12b175ba6c7bd66d99f1e30dfdbae263e0573"
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
