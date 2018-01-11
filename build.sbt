organization := "fr.acinq"

name := "bitcoin-lib"

version := "0.9.14-SNAPSHOT"

scalaVersion := "2.12.4"

scalacOptions ++= Seq("-deprecation", "-feature", "-language:implicitConversions,postfixOps")

libraryDependencies ++= Seq(
  "com.madgag.spongycastle" % "core" % "1.58.0.0",
  "com.google.protobuf" % "protobuf-java" % "2.5.0",
  "org.slf4j" % "slf4j-api" % "1.7.25",
  "ch.qos.logback" % "logback-classic" % "1.2.3" % "test",
  "com.google.guava" % "guava" % "19.0" % "test",
  "org.scalatest" %% "scalatest" % "3.0.3" % "test",
  "org.json4s" %% "json4s-jackson" % "3.5.2" % "test",
  "junit" % "junit" % "4.12" % "test",
)
