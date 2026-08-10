class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.2.5"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.5/vyql_v0.2.5_darwin_arm64.tar.gz"
      sha256 "4029c60fb31435498252d9049b8fa715bf86b15a9c6ee4f7f173a448dd6d5c26"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.5/vyql_v0.2.5_darwin_amd64.tar.gz"
      sha256 "22cfa36bf22b45aded2353b61996c8f11b433dc3b504fda5dbf6499c548a4559"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.5/vyql_v0.2.5_linux_arm64.tar.gz"
      sha256 "1efe2372910e69620bd42b7c778016e293ce85a6f3bd1c1b4b8da8328f86510a"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.2.5/vyql_v0.2.5_linux_amd64.tar.gz"
      sha256 "7f77beec702ef655f01d6a715cb71211af5f64e0c73c85d1f8cc9c7a11bb5d84"
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
