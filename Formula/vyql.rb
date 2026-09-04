class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.4.1"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.1/vyql_v0.4.1_darwin_arm64.tar.gz"
      sha256 "550f07fb8a32d1dd17f3ace5ca4cf931f7e03a90174d067d3cd2e8ddc6cd5aa3"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.1/vyql_v0.4.1_darwin_amd64.tar.gz"
      sha256 "b91f6be6618330acdb7d7e4f2d9509092eac11bd16b505aa392f8a51911d8a2e"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.1/vyql_v0.4.1_linux_arm64.tar.gz"
      sha256 "78cdf2f768e712fcea1dab583ca5a59158e34222fdb56346b7940d3fd9284535"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.1/vyql_v0.4.1_linux_amd64.tar.gz"
      sha256 "b06c95a2961e7df099f4f4072e11077e33bf4733f38873ec9afe9173596bc727"
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
