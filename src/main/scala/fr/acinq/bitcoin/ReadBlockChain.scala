package fr.acinq.bitcoin

import java.io._

object ReadBlockChain extends App {
  //val path = "/fabrice/shared/blk00001.dat" //  "/home/fabrice/.bitcoin/blocks/blk00001.dat"
  var path = ""
  var skip = 0
  var take = 0

  def parse(arguments: List[String]): Unit = arguments match {
    case Nil => ()
    case "-skip" :: value :: tail => skip = value.toInt; parse(tail)
    case "-take" :: value :: tail => take = value.toInt; parse(tail)
    case filename :: tail => path = filename; parse(tail)
  }

  parse(args.toList)

  println(s"reading blocks from $path")
  val file = new File(path)
  if (file.isDirectory) {
    file.listFiles(new FilenameFilter {
      override def accept(dir: File, name: String): Boolean = ???
    })
  }
  val input = new BufferedInputStream(new FileInputStream(path))

  def skipBlock(input: InputStream): Unit = {
    val magic = uint32(input)
    assert(magic == 0xd9b4bef9L)
    val size = uint32(input)
    input.skip(size)
  }

  var prev = ""
  def readBlock(input: InputStream, verbose: Boolean = false): Unit = {
    val magic = uint32(input)
    assert(magic == 0xd9b4bef9L)
    val size = uint32(input)
    val raw = new Array[Byte](size.toInt)
    input.read(raw)
    val block = Block.read(new ByteArrayInputStream(raw))
    val expected = toHexString(block.header.hashPreviousBlock)
    if (expected != prev) println("warning: expected previous hash does not match previous hash")
    prev = toHexString(block.hash)
  }

  for( i <- 1 to skip) skipBlock(input)
  var count = 0
  println
  while( (input.available() > 0) && !(take > 0 && count >= take)) {
    printf(s"\rparsing block $count")
    readBlock(input)
    count = count + 1
  }
  println
}
