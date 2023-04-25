# Custom VPC
resource "aws_vpc" "vpc" {
  cidr_block       = var.cidr_block_vpc
  instance_tenancy = "default"

  tags = {
    Name = var.vpc_name
  }
}

# create a public subnet 01
resource "aws_subnet" "pub_sbn1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_block_pub_sbn1
  availability_zone = var.az1

  tags = {
    Name = var.pub_sbn1
  }
}

resource "aws_subnet" "pub_sbn2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_block_pub_sbn2
  availability_zone = var.az2

  tags = {
    Name = var.pub_sbn2
  }
}

# create a private subnet 01
resource "aws_subnet" "pv_sbn1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_block_pv_sbn1
  availability_zone = var.az1

  tags = {
    Name = var.pv_sbn1
  }
}

# create a private subnet 02
resource "aws_subnet" "pv_sbn2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_block_pv_sbn2
  availability_zone = var.az2

  tags = {
    Name = var.pv_sbn2
  }
}

# create IGW
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = var.igw
  }
}

# create Elastic IP
resource "aws_eip" "eip" {
  vpc = true
  tags = {
    Name = var.eip
  }
}

# create Nat
resource "aws_nat_gateway" "ngw" {
  subnet_id     = aws_subnet.pub_sbn1.id
  allocation_id = aws_eip.eip.id

  tags = {
    Name = var.ngw
  }
}

# create Route Table Public SN
resource "aws_route_table" "pub_rt" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = var.cidr_block_all
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = var.pub_rt
  }
}

# create Route Table Private SN
resource "aws_route_table" "pv_rt" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = var.cidr_block_all
    nat_gateway_id = aws_nat_gateway.ngw.id
  }

  tags = {
    Name = var.pv_rt
  }
}

# create public subnet1 attached to public route table association
resource "aws_route_table_association" "pub_rta1" {
  subnet_id      = aws_subnet.pub_sbn1.id
  route_table_id = aws_route_table.pub_rt.id

}

# create public subnet2 attached to public route table association
resource "aws_route_table_association" "pub_rta2" {
  subnet_id      = aws_subnet.pub_sbn2.id
  route_table_id = aws_route_table.pub_rt.id

}

# create private subnet1 attached to private route table association
resource "aws_route_table_association" "pv_rta1" {
  subnet_id      = aws_subnet.pv_sbn1.id
  route_table_id = aws_route_table.pv_rt.id

}

# Private subnet2 attached to private route table
resource "aws_route_table_association" "pv_rta2" {
  subnet_id      = aws_subnet.pv_sbn2.id
  route_table_id = aws_route_table.pv_rt.id

}

# create Frontend SG
resource "aws_security_group" "FrontendSG" {
  name        = "FrontendSG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "TLS from VPC"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  ingress {
    description = "TLS from VPC"
    from_port   = var.port_http
    to_port     = var.port_http
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = var.sg
  }
}

# create Backend SG
resource "aws_security_group" "BackendSG" {
  name        = "BackendSG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "TLS from VPC"
    from_port   = var.port_mysql
    to_port     = var.port_mysql
    protocol    = "tcp"
    cidr_blocks = [var.cidr_block_pub_sbn1, var.cidr_block_pub_sbn2]

  }

  ingress {
    description = "TLS from VPC"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = [var.cidr_block_pub_sbn1, var.cidr_block_pub_sbn2]

  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = var.sg
  }
}

# create S3 media bucket 
resource "aws_s3_bucket" "s3bucketmedia1" {
  bucket        = var.s3bucketmedia1
  force_destroy = true

  tags = {
    Name        = var.s3bucketmedia1
    Environment = var.Environment
  }
}

#Create S3 code Bucket 
resource "aws_s3_bucket" "s3bucketcode11" {
  bucket        = var.s3bucketcode1
  force_destroy = true


  tags = {
    Name        = var.s3bucketcode1
    Environment = var.Environment
  }
}

##create bucket policy for media
resource "aws_s3_bucket_policy" "s3bucketmedia1_policy" {
  bucket = aws_s3_bucket.s3bucketmedia1.id
  policy = jsonencode({
    Id = "mediaBucketPolicy"
    Statement = [
      {
        Action = ["s3:GetObject", "s3:GetObjectVersion"]
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Resource = "arn:aws:s3:::s3bucketmedia1/*"
        Sid      = "PublicReadGetObject"
      }
    ]
    Version = "2012-10-17"
  })
}

#create s3 bucket log for media
resource "aws_s3_bucket" "s3bucketmediallog" {
  bucket        = "s3bucketmediallog"
  force_destroy = true
  tags = {
    Name = "s3bucketmediallog"
  }
}

#create bucket policy for medialog
resource "aws_s3_bucket_policy" "s3bucketmediallogpolicy" {
  bucket = aws_s3_bucket.s3bucketmediallog.id
  policy = jsonencode({
    Id = "mediaBucketlogsPolicy"
    Statement = [
      {
        Action = "s3:GetObject"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Resource = "arn:aws:s3:::s3bucketmediallog/*"
        Sid      = "PublicReadGetObject"
      }
    ]
    Version = "2012-10-17"
  })
}

# create DB Subnet group
resource "aws_db_subnet_group" "db_subnet" {
  name       = "db_subnet"
  subnet_ids = [aws_subnet.pv_sbn1.id, aws_subnet.pv_sbn2.id]

  tags = {
    Name = var.db_subnet_group
  }
}

# create RDS Mysql Database
resource "aws_db_instance" "db_instance" {
  allocated_storage      = 20
  identifier             = var.db_name
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t2.micro"
  db_name                = var.db_name
  username               = var.db_username
  password               = var.userpassword
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.db_subnet.id
  vpc_security_group_ids = [aws_security_group.BackendSG.id]
  publicly_accessible    = false
  multi_az               = true
}

# Create a key pair
resource "aws_key_pair" "keypair" {
  key_name   = var.keypair
  public_key = file(var.path-to-mypubkey)
}

#Create IAM role for EC2
resource "aws_iam_instance_profile" "IAM-Profile" {
  name = var.IAM-Profile
  role = aws_iam_role.IAM-Role.name
}
resource "aws_iam_role" "IAM-Role" {
  name        = var.IAM-Role
  description = "S3 Full Permission"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    tag-key = "IAM-Role"
  }
}

#IAM role Policy attachment
resource "aws_iam_role_policy_attachment" "IAM-role-pol-attach" {
  role       = aws_iam_role.IAM-Role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# create Ec2(webserver) and  word press configuration
resource "aws_instance" "webserver" {
  ami                         = var.ami-redhat
  instance_type               = var.instance_type
  vpc_security_group_ids      = [aws_security_group.FrontendSG.id]
  subnet_id                   = aws_subnet.pub_sbn1.id
  key_name                    = var.keypair
  iam_instance_profile        = aws_iam_instance_profile.IAM-Profile.id
  associate_public_ip_address = true

  user_data = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo yum install unzip -y
unzip awscliv2.zip
sudo ./aws/install
sudo yum install httpd php php-mysqlnd -y
cd /var/www/html
touch indextest.html
echo "This is a test file" > indextest.html
sudo yum install wget -y
wget https://wordpress.org/wordpress-5.1.1.tar.gz
tar -xzf wordpress-5.1.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress
rm -rf wordpress-5.1.1.tar.gz
chmod -R 755 wp-content
chown -R apache:apache wp-content
wget https://s3.amazonaws.com/bucketforwordpresslab-donotdelete/htaccess.txt
mv htaccess.txt .htaccess
cd /var/www/html && mv wp-config-sample.php wp-config.php
sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', '${var.db_name}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', '${var.db_username}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', '${var.db_passwd}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${element(split(":", aws_db_instance.db_instance.endpoint), 0)}' )@g" /var/www/html/wp-config.php
cat <<EOT> /etc/httpd/conf/httpd.conf
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin root@localhost
<Directory />
    AllowOverride none
    Require all denied
</Directory>
DocumentRoot "/var/www/html"
<Directory "/var/www">
    AllowOverride None
    # Allow open access:
    Require all granted
</Directory>
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
</Directory>
<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>
<Files ".ht*">
    Require all denied
</Files>
ErrorLog "logs/error_log"
LogLevel warn
<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common
    <IfModule logio_module>
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\" %I %O" combinedio
    </IfModule>
    CustomLog "logs/access_log" combined
</IfModule>
<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
</IfModule>
<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>
<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>
AddDefaultCharset UTF-8
<IfModule mime_magic_module>
        MIMEMagicFile conf/magic
</IfModule>
EnableSendfile on
IncludeOptional conf.d/*.conf
EOT
cat <<EOT> /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
rewriterule ^wp-content/uploads/(.*)$ http://${data.aws_cloudfront_distribution.cloudfront.domain_name}/\$1 [r=301,nc]
# BEGIN WordPress
# END WordPress
EOT
aws s3 cp --recursive /var/www/html/ s3://s3bucketcode1
aws s3 sync /var/www/html/ s3://s3bucketcode1
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync --delete s3://s3bucketcode1 /var/www/html/" > /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://s3bucketmedia1" >> /etc/crontab
sudo chkconfig httpd on
sudo service httpd start
sudo setenforce 0
  EOF
  tags = {
    Name = var.webserver_name
  }
}


# Cloudfront Distribution Data
data "aws_cloudfront_distribution" "cloudfront" {
  id = aws_cloudfront_distribution.cloudfront-distribution.id
}

# Cloudfront Distribution
locals {
  s3_origin_id = "aws_s3_bucket.s3bucketmedia1.id"
}
resource "aws_cloudfront_distribution" "cloudfront-distribution" {
  origin {
    domain_name = aws_s3_bucket.s3bucketmedia1.bucket_domain_name
    origin_id   = local.s3_origin_id
  }

  enabled = true

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 600
  }

  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

#create target group
resource "aws_lb_target_group" "tg" {
  name     = "tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 3
    interval            = 90
    timeout             = 60
    path                = "/indextest.html"
  }
}

#ceate Target Group Attachment
resource "aws_lb_target_group_attachment" "tga" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.webserver.id
  port             = 80
}

#Create Load Balancer
resource "aws_lb" "alb" {
  name                       = "alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.FrontendSG.id]
  subnets                    = [aws_subnet.pub_sbn1.id, aws_subnet.pub_sbn2.id]
  enable_deletion_protection = false
  access_logs {
    bucket = "aws_s3_bucket.alb.elblog"
    prefix = "alblog"
  }
}

#Create Load Balancer Listener
resource "aws_lb_listener" "lb-listener" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

#create AMI from Instance
resource "aws_ami_from_instance" "ami_from_instance" {
  name                    = "ami_from_instance"
  source_instance_id      = aws_instance.webserver.id
  snapshot_without_reboot = true
}

#Create timeout
resource "time_sleep" "wait_600_seconds" {
  depends_on = [aws_instance.webserver]

  create_duration = "600s"
}
#Create Launch Configuration
resource "aws_launch_configuration" "lc" {
  name_prefix                 = "lc"
  image_id                    = aws_ami_from_instance.ami_from_instance.id
  instance_type               = var.instance_type
  iam_instance_profile        = aws_iam_instance_profile.IAM-Profile.id
  security_groups             = ["${aws_security_group.FrontendSG.id}"]
  associate_public_ip_address = true
  depends_on                  = [time_sleep.wait_600_seconds]
  key_name                    = aws_key_pair.keypair.key_name
  user_data                   = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo yum install unzip -y
unzip awscliv2.zip
sudo ./aws/install
sudo yum install httpd php php-mysqlnd -y
cd /var/www/html
touch indextest.html
echo "This is a test file" > indextest.html
sudo yum install wget -y
wget https://wordpress.org/wordpress-5.1.1.tar.gz
tar -xzf wordpress-5.1.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress
rm -rf wordpress-5.1.1.tar.gz
chmod -R 755 wp-content
chown -R apache:apache wp-content
wget https://s3.amazonaws.com/bucketforwordpresslab-donotdelete/htaccess.txt
mv htaccess.txt .htaccess
cd /var/www/html && mv wp-config-sample.php wp-config.php
sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', '${var.db_name}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', '${var.db_username}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', '${var.db_passwd}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST','${element(split(":", aws_db_instance.db_instance.endpoint), 0)}' )@g" /var/www/html/wp-config.php
sudo sed -i  -e '154aAllowOverride All' -e '154d' /etc/httpd/conf/httpd.conf
cat <<EOT> /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
rewriterule ^wp-content/uploads/(.*)$ http://${data.aws_cloudfront_distribution.cloudfront.domain_name}/\$1 [r=301,nc]
# BEGIN WordPress
# END WordPress
EOT
aws s3 cp --recursive /var/www/html/ s3://cpds3codeb
aws s3 sync /var/www/html/ s3://cpds3codeb
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync --delete s3://cpds3codeb /var/www/html/" > /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://cpds3mediab" >> /etc/crontab
sudo chkconfig httpd on
sudo service httpd start
sudo setenforce 0
curl -Ls https://download.newrelic.com/install/newrelic-cli/scripts/install.sh | bash && sudo NEW_RELIC_API_KEY=NRAK-17LZQVZP6D524FYTU9ZH8F1SH4J NEW_RELIC_ACCOUNT_ID=3369793 NEW_RELIC_REGION=EU /usr/local/bin/newrelic install -n php-agent-installer -y
EOF
  lifecycle {
    create_before_destroy = false
  }
}

#create autoscaling group
resource "aws_autoscaling_group" "ASG" {
  name                      = "ASG"
  desired_capacity          = 3
  max_size                  = 4
  min_size                  = 2
  health_check_grace_period = 300
  default_cooldown          = 60
  health_check_type         = "ELB"
  force_delete              = true
  launch_configuration      = aws_launch_configuration.lc.name
  vpc_zone_identifier       = [aws_subnet.pub_sbn1.id, aws_subnet.pub_sbn2.id]
  target_group_arns         = ["${aws_lb_target_group.tg.arn}"]
  tag {
    key                 = "Name"
    value               = "asg"
    propagate_at_launch = true
  }
}

# Autoscaling Group Policy
resource "aws_autoscaling_policy" "asg_pol" {
  name                   = "asg_pol"
  policy_type            = "TargetTrackingScaling"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.ASG.name
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 60.0
  }
}

# create cloudwatch
resource "aws_cloudwatch_dashboard" "cw_dashboard" {
  dashboard_name = "cw_dashboard"
  dashboard_body = <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "CPUUtilization",
            "InstanceId",
            "${aws_instance.webserver.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "EC2 Instance CPU"
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "NetworkIn",
            "Instanceld",
            "${aws_instance.webserver.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "EC2 Network In"
      }
    }
  ]
}
EOF
}

# Create Cloudwatch metrics
resource "aws_cloudwatch_metric_alarm" "cw-metric-alarm" {
  alarm_name          = "cw-metric-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.ASG.name}"
  }
  alarm_description = "This metric monitors ec2 cpu utilization"
  alarm_actions     = [aws_autoscaling_policy.asg_pol.arn]
}

#Create cloudwatch metric alarm for health = usteam-metric-health-alarm
resource "aws_cloudwatch_metric_alarm" "cw-metric-health-alarm" {
  alarm_name          = "cw-metric-health-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "1"
  dimensions = {
    "AutoScalingGroupName" = "${aws_autoscaling_group.ASG.name}"
  }
  alarm_description = "This metric monitors ec2 health status"
  alarm_actions     = ["${aws_autoscaling_policy.asg_pol.arn}"]
}

#Create SNS Topic
resource "aws_sns_topic" "sns_alarms_topic" {
  name = "sns_alarms_topic"
  delivery_policy = jsonencode({
    "http" : {
      "defaultHealthyRetryPolicy" : {
        "minDelayTarget" : 20,
        "maxDelayTarget" : 20,
        "numRetries" : 3,
        "numMaxDelayRetries" : 0,
        "numNoDelayRetries" : 0,
        "numMinDelayRetries" : 0,
        "backoffFunction" : "linear"
      },
      "disableSubscriptionOverrides" : false,
      "defaultThrottlePolicy" : {
        "maxReceivesPerSecond" : 1
      }
    }
  })
}

locals {
  emails = ["kehinde.otogunwa@cloudhight.com", "adejare.adesina@cloudhight.com", "victor.eseyin@cloudhight.com", "ahmed.oyeyemi@cloudhight.com"]
}

#  Create Route 53 Hosted zone
resource "aws_route53_zone" "route53_zone" {
  name          = "mezonatechnologies.com"
  force_destroy = true
}

# Create A Route 53 record pointing to lb
resource "aws_route53_record" "route53_WWW" {
  zone_id = aws_route53_zone.route53_zone.zone_id
  name    = "mezonatechnologies.com"
  type    = "A"
  # ttl     = "300"
  #records = [aws_instance.webserver.public_ip]
  alias {
    name                   = aws_lb.alb.dns_name
    zone_id                = aws_lb.alb.zone_id
    evaluate_target_health = true
  }
}