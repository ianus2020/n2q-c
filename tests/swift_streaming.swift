// Appended to the implementation before its CLI/self-test by scripts/check.sh.
let testDir = FileManager.default.temporaryDirectory.appendingPathComponent("n2q-swift-"+UUID().uuidString)
try FileManager.default.createDirectory(at: testDir,withIntermediateDirectories:false)
defer {try? FileManager.default.removeItem(at:testDir)}
let source=testDir.appendingPathComponent("source"), destination=testDir.appendingPathComponent("out")
try Data("abcdef".utf8).write(to:source)
try Data("keep".utf8).write(to:destination)
let reader=try FileHandle(forReadingFrom:source)
let first=try readExact(reader,3)
precondition(first==[97,98,99])
let remaining=try readUpTo(reader,7)
precondition(remaining==[100,101,102])
do { _ = try readExact(reader,1);fatalError("truncation accepted") } catch {}
try reader.close()
do {
    try atomicFile(destination.path) { handle in
        try handle.write(contentsOf:Data("tentative".utf8))
        throw fileError()
    }
    fatalError("staging failure accepted")
} catch {}
let saved=try Data(contentsOf:destination)
precondition(saved==Data("keep".utf8))
let names=try FileManager.default.contentsOfDirectory(atPath:testDir.path)
precondition(names.count==2)
print("Swift bounded reads, truncation and staging cleanup PASS")
