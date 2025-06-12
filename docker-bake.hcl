group "default" {
  targets = ["app"]
}

target "app" {
  context = "."
  dockerfile = "./Dockerfile"
  tags = ["myapp:latest"]
  platforms = ["linux/amd64"]
}
