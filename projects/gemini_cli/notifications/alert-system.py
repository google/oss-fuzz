#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

"""
Automated Alert System for Gemini CLI OSS-Fuzz Integration
Provides intelligent notifications for deployment status, issues, and performance
"""

import asyncio
import json
import smtplib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
from dataclasses import dataclass
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('alert-system.log'),
        logging.StreamHandler()
    ]
)

@dataclass
class Alert:
    """Alert notification"""
    level: str  # info, warning, error, critical
    title: str
    message: str
    timestamp: datetime
    project: str
    metrics: Optional[Dict] = None

class AlertSystem:
    """Automated alert system for OSS-Fuzz integration"""
    
    def __init__(self, project_name: str = "gemini_cli"):
        self.project_name = project_name
        self.alert_history: List[Alert] = []
        self.notification_channels = self.load_notification_config()
        
    def load_notification_config(self) -> Dict:
        """Load notification configuration"""
        config_path = "notification-config.json"
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        else:
            # Default configuration
            return {
                "email": {
                    "enabled": False,
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "username": os.getenv("EMAIL_USERNAME"),
                    "password": os.getenv("EMAIL_PASSWORD"),
                    "recipients": ["oss-fuzz-team@google.com", "gemini-cli-maintainers@google.com"]
                },
                "slack": {
                    "enabled": False,
                    "webhook_url": os.getenv("SLACK_WEBHOOK_URL"),
                    "channel": "#oss-fuzz-alerts"
                },
                "github": {
                    "enabled": True,
                    "repository": "google/oss-fuzz",
                    "token": os.getenv("GITHUB_TOKEN")
                },
                "alert_levels": {
                    "info": ["email", "github"],
                    "warning": ["email", "slack", "github"],
                    "error": ["email", "slack", "github"],
                    "critical": ["email", "slack", "github"]
                }
            }
    
    async def check_deployment_status(self) -> Dict:
        """Check deployment status and trigger alerts if needed"""
        try:
            # Check OSS-Fuzz project status
            url = f"https://oss-fuzz.com/testcase?project={self.project_name}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                return {"status": "active", "url": url}
            else:
                await self.send_alert(
                    level="error",
                    title="OSS-Fuzz Project Inactive",
                    message=f"Project {self.project_name} is not responding (HTTP {response.status_code})"
                )
                return {"status": "inactive", "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            await self.send_alert(
                level="critical",
                title="OSS-Fuzz Connection Failed",
                message=f"Unable to connect to OSS-Fuzz: {str(e)}"
            )
            return {"status": "error", "error": str(e)}
    
    async def check_build_status(self) -> Dict:
        """Check build status and alert on failures"""
        try:
            # Simulate build status check
            build_url = f"https://oss-fuzz.com/build-status?project={self.project_name}"
            
            # In a real implementation, this would check actual build logs
            build_status = "success"  # Simulated
            
            if build_status != "success":
                await self.send_alert(
                    level="warning",
                    title="Build Failure Detected",
                    message=f"OSS-Fuzz build for {self.project_name} has failed"
                )
            
            return {
                "status": build_status,
                "url": build_url,
                "last_check": datetime.now().isoformat()
            }
            
        except Exception as e:
            await self.send_alert(
                level="error",
                title="Build Status Check Failed",
                message=f"Unable to check build status: {str(e)}"
            )
            return {"status": "error", "error": str(e)}
    
    async def check_coverage_threshold(self, coverage: float) -> None:
        """Check coverage thresholds and alert if below target"""
        if coverage < 80:
            await self.send_alert(
                level="warning",
                title="Low Code Coverage",
                message=f"Code coverage for {self.project_name} is {coverage:.1f}% (target: 80%)"
            )
        elif coverage < 60:
            await self.send_alert(
                level="error",
                title="Critical Low Coverage",
                message=f"Code coverage for {self.project_name} is critically low: {coverage:.1f}%"
            )
    
    async def check_bug_threshold(self, bugs_found: int) -> None:
        """Check bug thresholds and alert if too many bugs found"""
        if bugs_found > 10:
            await self.send_alert(
                level="critical",
                title="High Bug Count",
                message=f"Critical: {bugs_found} bugs found in {self.project_name}"
            )
        elif bugs_found > 5:
            await self.send_alert(
                level="warning",
                title="Elevated Bug Count",
                message=f"Warning: {bugs_found} bugs found in {self.project_name}"
            )
    
    async def check_performance_score(self, score: float) -> None:
        """Check performance score and alert if below threshold"""
        if score < 60:
            await self.send_alert(
                level="critical",
                title="Critical Performance Issue",
                message=f"Performance score for {self.project_name} is critically low: {score:.1f}%"
            )
        elif score < 80:
            await self.send_alert(
                level="warning",
                title="Performance Degradation",
                message=f"Performance score for {self.project_name} is below target: {score:.1f}%"
            )
    
    async def send_alert(self, level: str, title: str, message: str, metrics: Optional[Dict] = None) -> None:
        """Send alert through configured channels"""
        alert = Alert(
            level=level,
            title=title,
            message=message,
            timestamp=datetime.now(),
            project=self.project_name,
            metrics=metrics
        )
        
        # Add to history
        self.alert_history.append(alert)
        
        # Get channels for this alert level
        channels = self.notification_channels["alert_levels"].get(level, [])
        
        # Send through each channel
        for channel in channels:
            try:
                if channel == "email" and self.notification_channels["email"]["enabled"]:
                    await self.send_email_alert(alert)
                elif channel == "slack" and self.notification_channels["slack"]["enabled"]:
                    await self.send_slack_alert(alert)
                elif channel == "github" and self.notification_channels["github"]["enabled"]:
                    await self.send_github_alert(alert)
            except Exception as e:
                logging.error(f"Failed to send {channel} alert: {e}")
        
        logging.info(f"Alert sent: {level} - {title}")
    
    async def send_email_alert(self, alert: Alert) -> None:
        """Send email alert"""
        email_config = self.notification_channels["email"]
        
        if not email_config["enabled"]:
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = email_config["username"]
            msg['To'] = ", ".join(email_config["recipients"])
            msg['Subject'] = f"[OSS-Fuzz Alert] {alert.title}"
            
            body = f"""
            OSS-Fuzz Alert for {alert.project}
            
            Level: {alert.level.upper()}
            Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
            
            {alert.message}
            
            ---
            This is an automated alert from the OSS-Fuzz monitoring system.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"])
            server.starttls()
            server.login(email_config["username"], email_config["password"])
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Email alert sent to {email_config['recipients']}")
            
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")
    
    async def send_slack_alert(self, alert: Alert) -> None:
        """Send Slack alert"""
        slack_config = self.notification_channels["slack"]
        
        if not slack_config["enabled"]:
            return
        
        try:
            # Color coding for different alert levels
            colors = {
                "info": "#4285f4",
                "warning": "#f4b400",
                "error": "#db4437",
                "critical": "#ea4335"
            }
            
            payload = {
                "channel": slack_config["channel"],
                "attachments": [{
                    "color": colors.get(alert.level, "#666666"),
                    "title": alert.title,
                    "text": alert.message,
                    "fields": [
                        {
                            "title": "Project",
                            "value": alert.project,
                            "short": True
                        },
                        {
                            "title": "Level",
                            "value": alert.level.upper(),
                            "short": True
                        },
                        {
                            "title": "Time",
                            "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                            "short": True
                        }
                    ],
                    "footer": "OSS-Fuzz Monitoring System"
                }]
            }
            
            response = requests.post(slack_config["webhook_url"], json=payload)
            response.raise_for_status()
            
            logging.info(f"Slack alert sent to {slack_config['channel']}")
            
        except Exception as e:
            logging.error(f"Failed to send Slack alert: {e}")
    
    async def send_github_alert(self, alert: Alert) -> None:
        """Send GitHub issue/comment alert"""
        github_config = self.notification_channels["github"]
        
        if not github_config["enabled"]:
            return
        
        try:
            # Create GitHub issue for critical alerts
            if alert.level in ["critical", "error"]:
                issue_title = f"🚨 OSS-Fuzz Alert: {alert.title}"
                issue_body = f"""
                ## OSS-Fuzz Alert
                
                **Project**: {alert.project}
                **Level**: {alert.level.upper()}
                **Time**: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
                
                ### Message
                {alert.message}
                
                ### Metrics
                ```json
                {json.dumps(alert.metrics, indent=2) if alert.metrics else "No metrics available"}
                ```
                
                ---
                *This issue was automatically created by the OSS-Fuzz monitoring system.*
                """
                
                # This would use GitHub API to create an issue
                # For now, we'll log it
                logging.info(f"GitHub issue would be created: {issue_title}")
            
            # For warnings and info, create a comment on existing issues
            else:
                logging.info(f"GitHub comment would be created for: {alert.title}")
                
        except Exception as e:
            logging.error(f"Failed to send GitHub alert: {e}")
    
    async def send_deployment_success_notification(self) -> None:
        """Send deployment success notification"""
        await self.send_alert(
            level="info",
            title="Deployment Successful",
            message=f"Gemini CLI has been successfully deployed to OSS-Fuzz. Project: {self.project_name}"
        )
    
    async def send_weekly_summary(self) -> None:
        """Send weekly summary of alerts and metrics"""
        # Get alerts from the last week
        week_ago = datetime.now() - timedelta(days=7)
        weekly_alerts = [alert for alert in self.alert_history if alert.timestamp > week_ago]
        
        if weekly_alerts:
            summary = f"""
            ## Weekly OSS-Fuzz Summary for {self.project_name}
            
            **Period**: {week_ago.strftime('%Y-%m-%d')} to {datetime.now().strftime('%Y-%m-%d')}
            
            ### Alert Summary
            - Critical: {len([a for a in weekly_alerts if a.level == 'critical'])}
            - Error: {len([a for a in weekly_alerts if a.level == 'error'])}
            - Warning: {len([a for a in weekly_alerts if a.level == 'warning'])}
            - Info: {len([a for a in weekly_alerts if a.level == 'info'])}
            
            ### Recent Alerts
            """
            
            for alert in weekly_alerts[-5:]:  # Last 5 alerts
                summary += f"- **{alert.level.upper()}**: {alert.title} ({alert.timestamp.strftime('%Y-%m-%d %H:%M')})\n"
            
            await self.send_alert(
                level="info",
                title="Weekly Summary",
                message=summary
            )
    
    async def run_monitoring(self, check_interval: int = 300) -> None:
        """Run continuous monitoring and alerting"""
        logging.info(f"Starting alert system for {self.project_name}")
        logging.info(f"Check interval: {check_interval} seconds")
        
        while True:
            try:
                # Check deployment status
                deployment_status = await self.check_deployment_status()
                
                # Check build status
                build_status = await self.check_build_status()
                
                # Simulate metrics (in real implementation, these would come from the dashboard)
                coverage = 85.5  # Simulated
                bugs_found = 3   # Simulated
                performance_score = 92.0  # Simulated
                
                # Check thresholds
                await self.check_coverage_threshold(coverage)
                await self.check_bug_threshold(bugs_found)
                await self.check_performance_score(performance_score)
                
                # Log status
                logging.info(f"Monitoring check completed - Performance: {performance_score:.1f}%")
                
                # Wait for next check
                await asyncio.sleep(check_interval)
                
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying

async def main():
    """Main function to run the alert system"""
    alert_system = AlertSystem("gemini_cli")
    await alert_system.run_monitoring()

if __name__ == "__main__":
    asyncio.run(main())
