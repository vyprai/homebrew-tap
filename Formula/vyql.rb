class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.6.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.6.0/vyql_v0.6.0_darwin_arm64.tar.gz"
      sha256 "c095fc1b5ec17d8fd328119047a02128f3b3f452f5b9d92ccc49b79fb8f0dd36"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.6.0/vyql_v0.6.0_darwin_amd64.tar.gz"
      sha256 "80ac8d820874b0cab4fa2f8c516fb05c97e82d183c815335b6d6cb001d76da9c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.6.0/vyql_v0.6.0_linux_arm64.tar.gz"
      sha256 "497b311007677d2878274198ba1685ad9ef61d53db3cfb0f19f62cfb9347c632"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.6.0/vyql_v0.6.0_linux_amd64.tar.gz"
      sha256 "545cbc4af3758fd6f1f2e1261e73897926b676bbbbad405a303021ca29d4cba9"
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
