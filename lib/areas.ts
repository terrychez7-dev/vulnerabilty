// 인프라 영역 분류 규칙. 위에서부터 먼저 맞는 규칙이 적용됩니다.
// 검사 대상: "벤더 제품 취약점명" (소문자). 사내 자산에 맞게 자유롭게 수정하세요.
// 규칙을 바꾸면 다음 동기화 때 전체 KEV가 다시 분류됩니다.

export type AreaKey = "server_os" | "network" | "security" | "mgmt" | "middleware" | "backup" | "endpoint" | "app";

export const AREAS: { key: AreaKey; name: string; pattern: RegExp | null }[] = [
  {
    key: "server_os",
    name: "서버 OS·가상화",
    pattern:
      /\bwindows\b(?!.*sharepoint)|\blinux\b|\bkernel\b|vmware|esxi|vcenter|hyper-v|red ?hat|ubuntu|\bsuse\b|oracle linux|solaris|\baix\b|\bxen\b|proxmox|nutanix|citrix hypervisor|\bkvm\b|qemu|win32k|active directory|open management infrastructure|\bsudo\b|polkit|glibc|openssh/,
  },
  {
    key: "network",
    name: "네트워크·VPN·방화벽",
    pattern:
      /pan-os|globalprotect|fortios|fortigate|fortiproxy|fortiweb|connect secure|policy secure|pulse|netscaler|citrix adc|citrix gateway|big-ip|sd-wan|routeros|\bios xe\b|\bios xr\b|nx-os|\basa\b|firepower|check point|zyxel|sonicwall|\bsma\d|arista|velocloud|juniper|junos|draytek|tp-link|d-link|netgear|ubiquiti|watchguard|firebox|\bbind\b|loadmaster|dd-wrt|fortinet multiple products|switch|router|firewall|vpn/,
  },
  {
    key: "security",
    name: "보안 솔루션·관리 콘솔",
    pattern:
      /identity services engine|\bise\b|secure email|fortimail|fortisiem|fortimanager|fortianalyzer|forticlient ems|\bedr\b|\bsiem\b|trend micro|symantec|sophos|mcafee|trellix|cyberark|beyondtrust|secure firewall management|\bfmc\b|endpoint manager|epmm|mobileiron|defender|fortisandbox|ivanti sentry|cloud services appliance/,
  },
  {
    key: "mgmt",
    name: "운영·원격관리 도구",
    pattern:
      /manageengine|kaseya|screenconnect|papercut|simplehelp|n-central|solarwinds|nagios|saltstack|\bsalt\b|teamviewer|anydesk|\brmm\b|remote monitoring/,
  },
  {
    key: "middleware",
    name: "미들웨어·서버 SW",
    pattern:
      /struts|tomcat|weblogic|websphere|jboss|wildfly|wso2|sharepoint|exchange|proftpd|vsftpd|onlyoffice|confluence|jira|oracle|\bsap\b|apache|nginx|\biis\b|log4j|spring|php|sql server|mysql|postgres|redis|elasticsearch|kafka|activemq|rabbitmq|coldfusion|zimbra|exim|smartermail|crushftp|serv-u|goanywhere|accellion|moveit|wing ftp|\.net framework|rails|teamcity|gitlab|artifactory|jenkins|grafana|geoserver|imagemagick|roundcube|gitea|starlette|kestra|owncloud|nextcloud|mlflow|ray-project|litellm|langflow/,
  },
  {
    key: "backup",
    name: "백업·스토리지",
    pattern: /backup|veeam|acronis|ahsay|commvault|veritas|netbackup|\bnas\b|qnap|synology|netapp|storage (?:array|server|manager)/,
  },
  {
    key: "endpoint",
    name: "모바일·단말·브라우저",
    pattern: /\bapple\b|\bios\b|macos|android|pixel|samsung|chrom|firefox|safari|\bedge\b|\boffice\b|acrobat|reader|internet explorer|flash player|silverlight|\bword\b|\bexcel\b|powerpoint|winrar|whatsapp|qualcomm|chipset|gigabyte/,
  },
  { key: "app", name: "웹·업무 애플리케이션", pattern: null },
];

export const AREA_NAME: Record<string, string> = Object.fromEntries(AREAS.map((a) => [a.key, a.name]));

export function classify(vendor: string, product: string, name: string): AreaKey {
  const text = `${vendor} ${product} ${name}`.toLowerCase();
  for (const a of AREAS) {
    if (a.pattern && a.pattern.test(text)) return a.key;
  }
  return "app";
}
