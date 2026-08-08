#!/usr/bin/env python3
"""Risk assessment and severity assignment."""


from scanner.models import (
    DiscoveredResource,
    ResourceType,
    ScanTarget,
    SecretType,
    SecurityFinding,
    Severity,
)


class RiskAssessor:
    """
    Assesses risk levels for discovered resources.

    Considers:
    - Resource type
    - Accessibility
    - Content exposure
    - Secret presence
    - Context
    """

    # Risk scoring matrix
    RISK_MATRIX = {
        # (resource_type, has_secrets, is_accessible) -> base_severity

        # Source control exposure
        (ResourceType.SOURCE_CONTROL_EXPOSURE, True, True): Severity.CRITICAL,
        (ResourceType.SOURCE_CONTROL_EXPOSURE, False, True): Severity.CRITICAL,
        (ResourceType.SOURCE_CONTROL_EXPOSURE, True, False): Severity.INFORMATIONAL,  # Not accessible = not a risk
        (ResourceType.SOURCE_CONTROL_EXPOSURE, False, False): Severity.INFORMATIONAL,  # Not accessible = not a risk

        # Database exposure
        (ResourceType.DATABASE_EXPOSURE, True, True): Severity.CRITICAL,
        (ResourceType.DATABASE_EXPOSURE, False, True): Severity.CRITICAL,
        (ResourceType.DATABASE_EXPOSURE, True, False): Severity.INFORMATIONAL,  # Not accessible = not a risk
        (ResourceType.DATABASE_EXPOSURE, False, False): Severity.INFORMATIONAL,  # Not accessible = not a risk

        # Configuration exposure
        (ResourceType.CONFIGURATION_EXPOSURE, True, True): Severity.CRITICAL,
        (ResourceType.CONFIGURATION_EXPOSURE, False, True): Severity.HIGH,
        (ResourceType.CONFIGURATION_EXPOSURE, True, False): Severity.INFORMATIONAL,  # Not accessible = not a risk
        (ResourceType.CONFIGURATION_EXPOSURE, False, False): Severity.INFORMATIONAL,  # Not accessible = not a risk

        # Backup exposure
        (ResourceType.BACKUP_EXPOSURE, True, True): Severity.CRITICAL,
        (ResourceType.BACKUP_EXPOSURE, False, True): Severity.HIGH,
        (ResourceType.BACKUP_EXPOSURE, True, False): Severity.INFORMATIONAL,  # Not accessible = not a risk
        (ResourceType.BACKUP_EXPOSURE, False, False): Severity.INFORMATIONAL,  # Not accessible = not a risk

        # Log exposure
        (ResourceType.LOG_EXPOSURE, True, True): Severity.HIGH,
        (ResourceType.LOG_EXPOSURE, False, True): Severity.MEDIUM,
        (ResourceType.LOG_EXPOSURE, True, False): Severity.INFORMATIONAL,  # Not accessible = not a risk
        (ResourceType.LOG_EXPOSURE, False, False): Severity.INFORMATIONAL,  # Not accessible = not a risk

        # Directory listing
        (ResourceType.DIRECTORY_LISTING, True, True): Severity.MEDIUM,
        (ResourceType.DIRECTORY_LISTING, False, True): Severity.MEDIUM,
        (ResourceType.DIRECTORY_LISTING, True, False): Severity.INFORMATIONAL,  # Not accessible = not a risk
        (ResourceType.DIRECTORY_LISTING, False, False): Severity.INFORMATIONAL,  # Not accessible = not a risk

        # Sensitive documents
        (ResourceType.POTENTIAL_SENSITIVE_DOCUMENT, True, True): Severity.HIGH,
        (ResourceType.POTENTIAL_SENSITIVE_DOCUMENT, False, True): Severity.MEDIUM,
        (ResourceType.POTENTIAL_SENSITIVE_DOCUMENT, True, False): Severity.INFORMATIONAL,  # Not accessible = not a risk
        (ResourceType.POTENTIAL_SENSITIVE_DOCUMENT, False, False): Severity.INFORMATIONAL,  # Not accessible = not a risk

        # Public resources
        (ResourceType.PUBLIC_DOCUMENT, True, True): Severity.INFORMATIONAL,
        (ResourceType.PUBLIC_DOCUMENT, False, True): Severity.INFORMATIONAL,
        (ResourceType.PUBLIC_IMAGE, True, True): Severity.INFORMATIONAL,
        (ResourceType.PUBLIC_IMAGE, False, True): Severity.INFORMATIONAL,
        (ResourceType.PUBLIC_DATA, True, True): Severity.LOW,
        (ResourceType.PUBLIC_DATA, False, True): Severity.LOW,
        (ResourceType.PUBLIC_EXPECTED, True, True): Severity.INFORMATIONAL,
        (ResourceType.PUBLIC_EXPECTED, False, True): Severity.INFORMATIONAL,
    }

    def assess_resource(self, resource: DiscoveredResource) -> Severity:
        """
        Assess the risk level of a discovered resource.

        Args:
            resource: The resource to assess

        Returns:
            Severity level
        """
        has_secrets = len(resource.secrets) > 0
        is_accessible = resource.is_accessible

        # Look up in risk matrix
        key = (resource.resource_type, has_secrets, is_accessible)
        base_severity = self.RISK_MATRIX.get(key, Severity.INFORMATIONAL)

        # Upgrade severity if critical secrets present
        if has_secrets:
            for secret in resource.secrets:
                if secret.secret_type in [
                    SecretType.PRIVATE_KEY,
                    SecretType.AWS_CREDENTIALS,
                ]:
                    if base_severity != Severity.CRITICAL:
                        base_severity = Severity.CRITICAL
                        break

        # Additional severity modifiers
        base_severity = self._apply_context_modifiers(resource, base_severity)

        return base_severity

    def _apply_context_modifiers(
        self, resource: DiscoveredResource, base_severity: Severity
    ) -> Severity:
        """Apply contextual severity modifiers."""
        # Upgrade if it's a current exposure (not historical)
        if resource.is_current and base_severity == Severity.LOW:
            base_severity = Severity.MEDIUM

        # Upgrade if it's from a sensitive path
        if resource.url_info.path and any(
            sensitive in resource.url_info.path.lower()
            for sensitive in ["admin", "config", "backup", "database", "private"]
        ):
            if base_severity == Severity.INFORMATIONAL:
                base_severity = Severity.LOW
            elif base_severity == Severity.LOW:
                base_severity = Severity.MEDIUM

        return base_severity

    def create_finding(self, resource: DiscoveredResource, target: ScanTarget) -> SecurityFinding:
        """
        Create a security finding from a discovered resource.

        Args:
            resource: The discovered resource
            target: The scan target for context

        Returns:
            SecurityFinding with full details
        """
        severity = self.assess_resource(resource)

        title = self._generate_title(resource)
        description = self._generate_description(resource)
        evidence = self._generate_evidence(resource)
        remediation = self._generate_remediation(resource)

        return SecurityFinding(
            resource=resource,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation,
        )

    def _generate_title(self, resource: DiscoveredResource) -> str:
        """Generate a finding title."""
        type_to_title = {
            ResourceType.SOURCE_CONTROL_EXPOSURE: "Source Control Repository Exposed",
            ResourceType.DATABASE_EXPOSURE: "Database File Accessible",
            ResourceType.CONFIGURATION_EXPOSURE: "Configuration File Exposed",
            ResourceType.BACKUP_EXPOSURE: "Backup File Accessible",
            ResourceType.LOG_EXPOSURE: "Log File Exposed",
            ResourceType.DIRECTORY_LISTING: "Directory Listing Enabled",
            ResourceType.POTENTIAL_SENSITIVE_DOCUMENT: "Potentially Sensitive Document Accessible",
            ResourceType.PUBLIC_DOCUMENT: "Public Document",
            ResourceType.PUBLIC_IMAGE: "Public Image",
            ResourceType.PUBLIC_DATA: "Public Data File",
            ResourceType.PUBLIC_EXPECTED: "Public Resource",
            ResourceType.HISTORICAL_ONLY: "Historical Resource (No Longer Accessible)",
            ResourceType.NOT_ACCESSIBLE: "Resource Not Accessible",
            ResourceType.FALSE_POSITIVE: "False Positive",
        }

        base_title = type_to_title.get(resource.resource_type, "Resource Exposure")

        # Add detail about secrets if present
        if resource.secrets:
            base_title += f" (Contains {len(resource.secrets)} Potential Secret{'s' if len(resource.secrets) > 1 else ''})"

        return base_title

    def _generate_description(self, resource: DiscoveredResource) -> str:
        """Generate a finding description."""
        descriptions = {
            ResourceType.SOURCE_CONTROL_EXPOSURE: (
                "Source control repositories and configuration files are publicly accessible. "
                "This can expose proprietary code, credentials, internal structure, and "
                "development practices that could aid attackers in reconnaissance or "
                "identifying vulnerabilities."
            ),
            ResourceType.DATABASE_EXPOSURE: (
                "Database files or backups are publicly accessible. This can expose "
                "sensitive data, user information, authentication credentials, and "
                "internal data structures. Database files often contain hashes, salts, "
                "and sometimes plaintext credentials."
            ),
            ResourceType.CONFIGURATION_EXPOSURE: (
                "Configuration files containing application settings, database credentials, "
                "API keys, or other sensitive configuration are publicly accessible. "
                "Attackers can use this information to gain unauthorized access to "
                "systems and data."
            ),
            ResourceType.BACKUP_EXPOSURE: (
                "Backup files are publicly accessible. Backups often contain complete "
                "copies of databases, configurations, or sensitive files. Exposed backups "
                "can lead to complete system compromise."
            ),
            ResourceType.LOG_EXPOSURE: (
                "Log files are publicly accessible. Logs may contain sensitive information "
                "including user activity, error messages with stack traces, internal paths, "
                "session tokens, or API keys."
            ),
            ResourceType.DIRECTORY_LISTING: (
                "Directory listing is enabled, allowing anyone to view all files in the "
                "directory. This can expose backup files, configuration files, or other "
                "sensitive resources that shouldn't be publicly visible."
            ),
            ResourceType.POTENTIAL_SENSITIVE_DOCUMENT: (
                "A document that may contain sensitive information is publicly accessible. "
                "Review the content to determine if it contains confidential business "
                "information, internal procedures, or sensitive data."
            ),
        }

        base_desc = descriptions.get(
            resource.resource_type,
            "A resource is publicly accessible that may require review."
        )

        # Add status information
        status_info = ""
        if resource.is_current:
            if resource.is_accessible:
                status_info = " This resource is currently accessible."
            else:
                status_info = " This resource was discovered but is not currently accessible."
        else:
            status_info = " This resource was found in historical records but is no longer accessible."

        return base_desc + status_info

    def _generate_evidence(self, resource: DiscoveredResource) -> str:
        """Generate evidence for the finding."""
        evidence_parts = []

        # URL information
        evidence_parts.append(f"URL: {resource.url_info.url}")
        evidence_parts.append(f"Discovery Source: {resource.url_info.discovery_source.value}")

        # HTTP response information
        if resource.http_response:
            evidence_parts.append(f"HTTP Status: {resource.http_response.status_code}")
            if resource.http_response.content_type:
                evidence_parts.append(f"Content-Type: {resource.http_response.content_type}")
            if resource.http_response.server:
                evidence_parts.append(f"Server: {resource.http_response.server}")

        # Secrets found
        if resource.secrets:
            evidence_parts.append("\nSecrets Detected:")
            for secret in resource.secrets:
                evidence_parts.append(
                    f"  - {secret.secret_type.value}: {secret.redacted_value} "
                    f"(confidence: {secret.confidence:.0%})"
                )

        # Directory listing
        if resource.http_response and resource.http_response.is_directory_listing:
            evidence_parts.append("Directory listing is ENABLED on this resource")

        return "\n".join(evidence_parts)

    def _generate_remediation(self, resource: DiscoveredResource) -> str:
        """Generate remediation advice."""
        remediations = {
            ResourceType.SOURCE_CONTROL_EXPOSURE: (
                "1. Remove .git directory and all source control files from public web directories\n"
                "2. Ensure .gitignore is properly configured to prevent future commits\n"
                "3. Review any potentially exposed code for credentials or sensitive data\n"
                "4. Rotate any credentials that may have been exposed\n"
                "5. Configure web server to deny access to .git and source control directories"
            ),
            ResourceType.DATABASE_EXPOSURE: (
                "1. Immediately remove database files from public directories\n"
                "2. Review database contents for exposed sensitive information\n"
                "3. Move database files to non-web-accessible locations\n"
                "4. Ensure proper file permissions on database directories\n"
                "5. Rotate database credentials if exposed"
            ),
            ResourceType.CONFIGURATION_EXPOSURE: (
                "1. Remove configuration files from public directories\n"
                "2. Review configuration for exposed credentials and rotate them\n"
                "3. Use environment variables or secure vaults for sensitive configuration\n"
                "4. Ensure .env files are in .gitignore and not deployed\n"
                "5. Implement proper file permissions on configuration files"
            ),
            ResourceType.BACKUP_EXPOSURE: (
                "1. Remove backup files from public directories\n"
                "2. Store backups in secure, non-web-accessible locations\n"
                "3. Encrypt backup files\n"
                "4. Implement proper access controls on backup storage\n"
                "5. Review backup contents for sensitive data"
            ),
            ResourceType.LOG_EXPOSURE: (
                "1. Remove log files from public directories\n"
                "2. Store logs in non-web-accessible directories\n"
                "3. Implement log rotation and secure deletion\n"
                "4. Review logging practices to avoid logging sensitive information\n"
                "5. Ensure proper file permissions on log directories"
            ),
            ResourceType.DIRECTORY_LISTING: (
                "1. Disable directory listing in web server configuration\n"
                "   - Apache: Remove 'Indexes' option or use 'Options -Indexes'\n"
                "   - Nginx: Ensure 'autoindex off;' directive\n"
                "   - IIS: Disable directory browsing\n"
                "2. Add default index pages to directories\n"
                "3. Review directory contents for sensitive files"
            ),
            ResourceType.POTENTIAL_SENSITIVE_DOCUMENT: (
                "1. Review document content to determine sensitivity\n"
                "2. Remove or restrict access to sensitive documents\n"
                "3. Implement access controls if document should be internal only\n"
                "4. Consider document classification and access policies"
            ),
        }

        base_remediation = remediations.get(
            resource.resource_type,
            "Review the resource to determine if it should be publicly accessible. "
            "If not, remove it from public access or implement proper authentication."
        )

        return base_remediation

    def categorize_resources(
        self, resources: list[DiscoveredResource]
    ) -> dict[str, list[DiscoveredResource]]:
        """
        Categorize resources by type for reporting.

        Returns:
            Dictionary with resource types as keys and lists of resources as values
        """
        categories = {
            "documents": [],
            "images": [],
            "data_files": [],
            "configuration_files": [],
            "backup_files": [],
            "logs": [],
            "directory_listings": [],
            "historical": [],
            "not_accessible": [],
        }

        for resource in resources:
            if resource.resource_type in [
                ResourceType.PUBLIC_DOCUMENT,
                ResourceType.POTENTIAL_SENSITIVE_DOCUMENT,
            ]:
                categories["documents"].append(resource)

            elif resource.resource_type == ResourceType.PUBLIC_IMAGE:
                categories["images"].append(resource)

            elif resource.resource_type in [ResourceType.PUBLIC_DATA, ResourceType.DATABASE_EXPOSURE]:
                categories["data_files"].append(resource)

            elif resource.resource_type == ResourceType.CONFIGURATION_EXPOSURE:
                categories["configuration_files"].append(resource)

            elif resource.resource_type == ResourceType.BACKUP_EXPOSURE:
                categories["backup_files"].append(resource)

            elif resource.resource_type == ResourceType.LOG_EXPOSURE:
                categories["logs"].append(resource)

            elif resource.resource_type == ResourceType.DIRECTORY_LISTING:
                categories["directory_listings"].append(resource)

            if not resource.is_current:
                categories["historical"].append(resource)

            if not resource.is_accessible:
                categories["not_accessible"].append(resource)

        return categories