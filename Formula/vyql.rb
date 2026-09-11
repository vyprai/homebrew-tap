class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.6.1"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.6.1/vyql_v0.6.1_darwin_arm64.tar.gz"
      sha256 "73b11f565ccf74a83f42588b99b572e9222f3cdad1dad29bfc8ba97651d6f65f"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.6.1/vyql_v0.6.1_darwin_amd64.tar.gz"
      sha256 "7b2cb0d8adf9e732817dca6175487aca92590a69aab1007297fa569b1cac1c76"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.6.1/vyql_v0.6.1_linux_arm64.tar.gz"
      sha256 "991b3964170fcdaefe40f937a87d33f9d282340ee5b7840f326a4a7e927f5d57"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.6.1/vyql_v0.6.1_linux_amd64.tar.gz"
      sha256 "67b4fa9d9798755620130845e1531af9c1b18209bb137f14e29d4fadd98285b2"
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
