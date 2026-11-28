require "json"
require "optparse"
require "time"
require "rugged"
require "linguist"

options = { repo: "/repo", ref: "HEAD" }
OptionParser.new do |parser|
  parser.on("--repo PATH") { |value| options[:repo] = value }
  parser.on("--ref REF") { |value| options[:ref] = value }
end.parse!

repository = Rugged::Repository.new(options[:repo])
object = repository.rev_parse(options[:ref])
commit = object.is_a?(Rugged::Commit) ? object : object.target
files = []

commit.tree.walk(:preorder) do |directory, entry|
  next unless entry[:type] == :blob

  path = File.join(directory, entry[:name]).tr("\\", "/").sub(%r{\A/}, "")
  blob = Linguist::LazyBlob.new(repository, entry[:oid], path)
  begin
    language = blob.language
  rescue StandardError => error
    raise "failed to classify #{path.inspect}: #{error.message}"
  end
  files << {
    path: path,
    bytes: blob.size,
    language: language&.name,
    color: language&.color,
    text: blob.text?,
    generated: blob.generated?,
    vendored: blob.vendored?,
    mime_type: blob.mime_type,
  }
end

puts JSON.generate(
  {
    commit: commit.oid,
    generated_at: commit.time.utc.iso8601,
    files: files.sort_by { |file| file[:path] },
  },
)
