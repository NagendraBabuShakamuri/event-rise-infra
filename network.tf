resource "aws_vpc" "dev-vpc" {
  cidr_block = var.cidr_block

  tags = {
    Name = "${var.aws_profile}-vpc"
  }
}

data "aws_availability_zones" "all" {
  state = "available"
}

resource "aws_subnet" "public-subnet" {
  count                   = var.public_subnets
  vpc_id                  = aws_vpc.dev-vpc.id
  cidr_block              = cidrsubnet(var.cidr_block, 8, count.index)
  availability_zone       = element(data.aws_availability_zones.all.names, count.index % length(data.aws_availability_zones.all.names))
  map_public_ip_on_launch = "true"

  tags = {
    Name = "${aws_vpc.dev-vpc.id}-Public subnet ${count.index + 1}"
  }
}

resource "aws_subnet" "private-subnet" {
  count             = var.private_subnets
  vpc_id            = aws_vpc.dev-vpc.id
  cidr_block        = cidrsubnet(var.cidr_block, 4, count.index + 1)
  availability_zone = element(data.aws_availability_zones.all.names, count.index % length(data.aws_availability_zones.all.names))

  tags = {
    Name = "${aws_vpc.dev-vpc.id}-Private subnet ${count.index + 1}"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.dev-vpc.id

  tags = {
    "Name" = "Internet-gateway"
  }
}

resource "aws_route_table" "public-route-table" {
  vpc_id = aws_vpc.dev-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
  tags = {
    "Name" = "Public-route-table"
  }
}

resource "aws_route_table" "private-route-table" {
  vpc_id = aws_vpc.dev-vpc.id
  tags = {
    "Name" = "Private-route-table"
  }
}

resource "aws_route_table_association" "public-route-table-association" {
  count          = var.public_subnets
  subnet_id      = aws_subnet.public-subnet[count.index].id
  route_table_id = aws_route_table.public-route-table.id
}

resource "aws_route_table_association" "private-route-table-association" {
  count          = var.private_subnets
  subnet_id      = aws_subnet.private-subnet[count.index].id
  route_table_id = aws_route_table.private-route-table.id
}

resource "aws_security_group" "app-lb-sg" {
  name        = "${var.aws_profile}-app-load-balancer-sg"
  description = "Load balancer security group to allow inbound traffic from the Internet"
  vpc_id      = aws_vpc.dev-vpc.id
  depends_on  = [aws_vpc.dev-vpc]

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.aws_profile}-app-load-balancer-sg"
  }
}

resource "aws_security_group" "app-sg" {
  name        = "${var.aws_profile}-application-sg"
  description = "Default security group to allow inbound/outbound from the VPC"
  vpc_id      = aws_vpc.dev-vpc.id
  depends_on  = [aws_vpc.dev-vpc]
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.app-lb-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.aws_profile}-application-sg"
  }
}

resource "aws_security_group" "db-sg" {
  name        = "${var.aws_profile}-database-sg"
  description = "Database security group to allow inbound/outbound from the VPC"
  vpc_id      = aws_vpc.dev-vpc.id
  depends_on  = [aws_vpc.dev-vpc]
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app-sg.id]
  }
  tags = {
    Name = "${var.aws_profile}-database-sg"
  }
}

# Create a DB subnet group
resource "aws_db_subnet_group" "private_db_subnet_group" {
  name = "private_db_subnet_group"
  subnet_ids = [for s in aws_subnet.private-subnet : s.id]
}

resource "aws_kms_key" "rds_kms_key" {
  description = "My Docdb KMS key"
}

#MongoDB database

resource "aws_docdb_cluster" "mongodb" {
  cluster_identifier      = "my-mongodb-cluster"
  engine                  = "docdb"
  master_username         = var.db_username
  master_password         = var.db_password
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.rds_kms_key.arn
  db_subnet_group_name    = aws_db_subnet_group.private_db_subnet_group.name
  vpc_security_group_ids  = [aws_security_group.db-sg.id]
  skip_final_snapshot     = true
}

#Get the latest AMI.

data "aws_ami" "custom_ami" {
  most_recent = true
  filter {
    name   = "name"
    values = ["info6150*"]
  }
}

# Generate a random name for the S3 bucket.

resource "random_id" "random" {
  byte_length = 4
}

#Create a private S3 bucket.

resource "aws_s3_bucket" "private_bucket" {
  bucket        = "my-${var.aws_profile}-bucket-${random_id.random.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "app" {
  bucket                  = aws_s3_bucket.private_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "this" {
  bucket = aws_s3_bucket.private_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.private_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.private_bucket.id
  rule {
    id     = "transition_to_standard_ia"
    status = "Enabled"
    filter {}
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

# Create an IAM Role for S3 Access.

resource "aws_iam_role" "EC2-EventRise" {
  name = "EC2-EventRise"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Create an S3 access policy to the above role.

resource "aws_iam_policy" "WebAppS3" {
  name        = "WebAppS3"
  description = "Policy for accessing S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.private_bucket.arn}",
          "${aws_s3_bucket.private_bucket.arn}/*"
        ]
      }
    ]
  })
}

# Attach the policy to the created role.

resource "aws_iam_role_policy_attachment" "s3_access_role_attachment" {
  policy_arn = aws_iam_policy.WebAppS3.arn
  role       = aws_iam_role.EC2-EventRise.name
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.EC2-EventRise.name
}

# Application load balancer
resource "aws_lb" "app-lb" {
  name               = "${var.aws_profile}-app-load-balancer"
  internal           = false
  load_balancer_type = "application"
  subnets            = [for s in aws_subnet.public-subnet : s.id]
  security_groups    = [aws_security_group.app-lb-sg.id]

  tags = {
    Name = "${var.aws_profile}-app-load-balancer"
  }
}

# Target group
resource "aws_lb_target_group" "webapp_tg" {
  name        = "webapp-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.dev-vpc.id
  target_type = "instance"
  health_check {
    enabled             = true
    interval            = 60
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 2
    healthy_threshold   = 2
    unhealthy_threshold = 5
  }
}

data "aws_acm_certificate" "ssl_certificate" {
  domain   = "${var.domain}"
  statuses = ["ISSUED"]
}

resource "aws_lb_listener" "webapp_listener" {
  load_balancer_arn = aws_lb.app-lb.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = data.aws_acm_certificate.ssl_certificate.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.webapp_tg.arn
  }
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "ebs_kms_key" {
  description             = "Symmetric customer-managed KMS key for EBS"
  deletion_window_in_days = 10
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Sid" : "Enable IAM User Permissions",
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Action" : "kms:*",
      "Resource" : "*"
      },
      {
        "Sid" : "Allow service-linked role use of the customer managed key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow attachment of persistent resources",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:CreateGrant"
        ],
        "Resource" : "*",
        "Condition" : {
          "Bool" : {
            "kms:GrantIsForAWSResource" : true
          }
        }
      }
    ]
  })
}

# Launch Configuration
resource "aws_launch_template" "asg_launch_template" {
  name          = "asg-launch-config"
  image_id      = data.aws_ami.custom_ami.id
  instance_type = "t2.micro"
  # key_name                = aws_key_pair.ec2keypair.key_name
  ebs_optimized           = false
  disable_api_termination = false

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.app-sg.id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 10
      volume_type           = "gp2"
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.ebs_kms_key.arn
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "Webapp EC2 Instance"
    }
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash    
    
    echo "[Unit]
    Description=app.js - making your environment variables
    Documentation=https://example.com
    Wants=network-online.target
    After=network-online.target

    [Service]
    Environment="AWS_DEFAULT_REGION=${var.region}"
    Environment="S3_BUCKET=${aws_s3_bucket.private_bucket.id}"
    Environment="DATABASE=${var.db_name}"
    Environment="HOST=${aws_docdb_cluster.mongodb.endpoint}"
    Environment="USER_NAME=${aws_docdb_cluster.mongodb.master_username}"
    Environment="PASSWORD=${var.db_password}"
    Environment="CLIENT_ID=${var.CLIENT_ID}"
    Environment="CLIENT_SECRET=${var.CLIENT_SECRET}"
    Type=simple
    User=ec2-user
    WorkingDirectory=/home/ec2-user/event-rise-apis/
    ExecStart=/usr/bin/node app.js
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target" > /etc/systemd/system/eventrise_apis.service

    sudo systemctl daemon-reload
    sudo systemctl enable eventrise_apis.service
    sudo systemctl start eventrise_apis.service

    echo "[Unit]
    Description=app.js - making your environment variables
    Documentation=https://example.com
    Wants=network-online.target
    After=network-online.target

    [Service]
    Type=simple
    User=ec2-user
    WorkingDirectory=/home/ec2-user/eventrise/
    ExecStart=/usr/bin/npm start
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target" > /etc/systemd/system/eventrise.service

    sudo systemctl daemon-reload
    sudo systemctl enable eventrise.service
    sudo systemctl start eventrise.service

    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-config.json \
    -s

    sudo systemctl start amazon-cloudwatch-agent

    sudo systemctl enable amazon-cloudwatch-agent
  EOF
  )

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.name
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "webapp_asg" {
  name                = "webapp-asg"
  target_group_arns   = [aws_lb_target_group.webapp_tg.arn]
  vpc_zone_identifier = [for s in aws_subnet.public-subnet : s.id]
  launch_template {
    id      = aws_launch_template.asg_launch_template.id
    version = "$Latest"
  }
  min_size                  = 1
  max_size                  = 3
  desired_capacity          = 1
  health_check_type         = "ELB"
  health_check_grace_period = 120
  default_cooldown          = 60
  tag {
    key                 = "Name"
    value               = "WebApp EC2 Instance"
    propagate_at_launch = true
  }
}

resource "aws_cloudwatch_metric_alarm" "scale_up_alarm" {
  alarm_name          = "high-cpu-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 5
  alarm_description   = "This metric checks if CPU usage is higher than 5% in the past 2 min"
  alarm_actions       = [aws_autoscaling_policy.scale_up_policy.arn]
  actions_enabled     = true
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.webapp_asg.name
  }
}

resource "aws_cloudwatch_metric_alarm" "scale_down_alarm" {
  alarm_name          = "low-cpu-usage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 3
  alarm_description   = "This metric checks if CPU usage is lower than 3% for the past 2 min"
  alarm_actions       = [aws_autoscaling_policy.scale_down_policy.arn]
  actions_enabled     = true
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.webapp_asg.name
  }
}

# Scale up policy
resource "aws_autoscaling_policy" "scale_up_policy" {
  name                   = "webapp_scale-up-policy"
  policy_type            = "SimpleScaling"
  autoscaling_group_name = aws_autoscaling_group.webapp_asg.name
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
}

# Scale down policy
resource "aws_autoscaling_policy" "scale_down_policy" {
  name                   = "webapp_scale-down-policy"
  policy_type            = "SimpleScaling"
  autoscaling_group_name = aws_autoscaling_group.webapp_asg.name
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.EC2-EventRise.name
}

# Create access key pair.

resource "aws_key_pair" "ec2keypair" {
  key_name   = "ec2.pub"
  public_key = file("~/.ssh/ec2.pub")
}

data "aws_route53_zone" "selected" {
  name = "${var.domain}"
}

# Create a new A record that points to the Load balancer.

resource "aws_route53_record" "new_record" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = data.aws_route53_zone.selected.name
  type    = "A"
  alias {
    name                   = aws_lb.app-lb.dns_name
    zone_id                = aws_lb.app-lb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_cloudwatch_log_group" "webapp_log_group" {
  name = "info6150"
}