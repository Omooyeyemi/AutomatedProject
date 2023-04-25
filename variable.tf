variable "cidr_block_vpc" {
  default = "10.0.0.0/16"
}

variable "cidr_block_all" {
  default = "0.0.0.0/0"
}
variable "cidr_block_pub_sbn1" {
  default = "10.0.1.0/24"

}

variable "cidr_block_pub_sbn2" {
  default = "10.0.2.0/24"
}

variable "cidr_block_pv_sbn1" {
  default = "10.0.3.0/24"
}

variable "cidr_block_pv_sbn2" {
  default = "10.0.4.0/24"
}
variable "vpc_name" {
  default = "usteam3"
}



variable "az1" {
  default = "us-east-1a"

}
variable "az2" {
  default = "us-east-1b"

}

variable "pub_sbn1" {
  default = "usteam3"

}

variable "pub_sbn2" {
  default = "usteam3"

}
variable "pv_sbn1" {
  default = "usteam3"

}
variable "pv_sbn2" {
  default = "usteam3"

}

variable "igw" {
  default = "usteam3_igw"

}

variable "ngw" {
  default = "usteam3_ngw"

}

variable "eip" {
  default = "usteam3_elastic_ip"

}

variable "pub_rt" {
  default = "usteam3_rt"

}

variable "pv_rt" {
  default = "usteam3_rt"

}

variable "port_ssh" {
  default = 22
}
variable "port_mysql" {
  default = 3306
}
variable "port_http" {
  default = 80
}
variable "sg" {
  default = "usteam3_SG"

}

variable "s3bucketmedia1" {
  default = "s3bucketmedia1"
}

variable "s3bucketcode1" {
  default = "s3bucketcode1"
}

variable "Environment" {
  default = "Dev"

}

variable "db_subnet_group" {
  default = "usteam3_db_subnet_gp"

}
variable "db_instance" {
  default = "usteam3_db_instance"

}
variable "db_name" {
  default = "wordpressdb"

}
variable "username" {
  default = "admin"

}
variable "userpassword" {
  default = "admin123"

}

variable "IAM-Profile" {
  default = "usteam3_IAM-Profile"

}

variable "IAM-Role" {
  default = "usteam3_IAM-Role"

}
variable "webserver" {
  default = "webserver"

}

variable "keypair" {
  default = "usteam3kp"

}
variable "path-to-mypubkey" {
  default = "~/Keypairs/usteam3kp.pub"

}
variable "ami-redhat" {
  default = "ami-06640050dc3f556bb" #"ami-016eb5d644c333ccb"

}
variable "instance_type" {
  default = "t2.micro"

}
variable "webserver_name" {
  default = "usteam3_webserver"

}
variable "cloudfront_distribution" {
  default = "usteam-distribution"
}

variable "db_username" {
  default = "admin"
}

variable "db_passwd" {
  default = "Admin123"

}