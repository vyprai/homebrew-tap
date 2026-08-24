class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.4.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.0/vyql_v0.4.0_darwin_arm64.tar.gz"
      sha256 "821bb125447596bf93d611e7741fae955f88617391287b7f3dd667ed7c5543d6"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.0/vyql_v0.4.0_darwin_amd64.tar.gz"
      sha256 "9161a77cc4445218589fd69858122b29c1b6dde4addb961458c6aed9f3883241"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.0/vyql_v0.4.0_linux_arm64.tar.gz"
      sha256 "49765fda4ca7cd690e3d782df1d62c420f40ebbaafdacd70360f815b8f2b685f"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.0/vyql_v0.4.0_linux_amd64.tar.gz"
      sha256 "182385bbc6fb8a9953c147d531c30de84435faccb8e432173e247f826b0f6696"
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
