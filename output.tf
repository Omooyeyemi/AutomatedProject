output "public_ip" {
  value = aws_instance.webserver.public_ip
}

output "cloudfront_domain_name" {
  value = aws_cloudfront_distribution.cloudfront-distribution.domain_name
}