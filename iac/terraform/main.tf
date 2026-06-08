# Terraform deployment configuration for Sentient AI dedicated audit VM on AWS

terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# 1. VPC & Networking
resource "aws_vpc" "sentient_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "sentient-vpc"
  }
}

resource "aws_subnet" "sentient_subnet" {
  vpc_id                  = aws_vpc.sentient_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"
  tags = {
    Name = "sentient-subnet"
  }
}

resource "aws_internet_gateway" "sentient_igw" {
  vpc_id = aws_vpc.sentient_vpc.id
  tags = {
    Name = "sentient-igw"
  }
}

resource "aws_route_table" "sentient_rt" {
  vpc_id = aws_vpc.sentient_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sentient_igw.id
  }
  tags = {
    Name = "sentient-route-table"
  }
}

resource "aws_route_table_association" "sentient_rta" {
  subnet_id      = aws_subnet.sentient_subnet.id
  route_table_id = aws_route_table.sentient_rt.id
}

# 2. Security Group
resource "aws_security_group" "sentient_sg" {
  name        = "sentient-security-group"
  description = "Allow inbound SSH and Streamlit dashboard access"
  vpc_id      = aws_vpc.sentient_vpc.id

  # SSH Access
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  # Streamlit App Access
  ingress {
    description = "Streamlit web UI"
    from_port   = 8501
    to_port     = 8501
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  # Outbound rules (Required to pull Docker images, LLM models and security templates)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Dedicated Ubuntu EC2 Instance
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "sentient_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.sentient_subnet.id
  vpc_security_group_ids = [aws_security_group.sentient_sg.id]
  key_name               = var.ssh_key_name

  root_block_device {
    volume_size           = 100 # 100 GB SSD to fit LLM models and Docker containers
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "sentient-ai-audit-server"
  }
}
