package com.shapesecurity.salvation2;

import com.shapesecurity.salvation2.Directives.HostSourceDirective;
import com.shapesecurity.salvation2.URLs.URI;
import com.shapesecurity.salvation2.Values.Host;
import com.shapesecurity.salvation2.Values.Scheme;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

// Read-only static analysis of an already-parsed Policy. It never mutates the policy,
// so querying and serialization behavior are unchanged; see Policy#audit.
final class PolicyAuditor {

	private PolicyAuditor() {
		// Utility class
	}

	@Nonnull
	static List<AuditDiagnostic> audit(@Nonnull Policy policy, int policyIndex) {
		List<AuditDiagnostic> findings = new ArrayList<>();
		List<Policy.NamedDirectiveView> directives = policy.getNamedDirectives();
		for (int directiveIndex = 0; directiveIndex < directives.size(); ++directiveIndex) {
			Policy.NamedDirectiveView entry = directives.get(directiveIndex);
			if (!(entry.getDirective() instanceof HostSourceDirective)) {
				continue;
			}
			auditHostSourceDirective(policyIndex, directiveIndex, entry.getLowcaseName(),
					(HostSourceDirective) entry.getDirective(), findings);
		}
		return findings;
	}

	private static void auditHostSourceDirective(int policyIndex, int directiveIndex, @Nonnull String directiveName,
			@Nonnull HostSourceDirective directive, @Nonnull List<AuditDiagnostic> findings) {
		List<String> values = directive.getValues();

		boolean hasNone = false;
		for (String value : values) {
			if (value.toLowerCase(Locale.ENGLISH).equals("'none'")) {
				hasNone = true;
				break;
			}
		}

		List<Scheme> schemes = directive.getSchemes();
		List<HostEntry> hostEntries = new ArrayList<>();

		for (int valueIndex = 0; valueIndex < values.size(); ++valueIndex) {
			String token = values.get(valueIndex);
			if (token.toLowerCase(Locale.ENGLISH).equals("'none'")) {
				continue;
			}
			if (hasNone) {
				findings.add(new AuditDiagnostic(
						AuditDiagnostic.UNREACHABLE_SOURCE,
						Policy.Severity.Error,
						policyIndex, directiveIndex, valueIndex, directiveName, token,
						"Source-expression \"" + token + "\" can never match anything, because this directive also contains 'none'",
						null));
			}
			if (token.equals("*") || Scheme.parseScheme(token).isPresent()) {
				continue;
			}
			Optional<Host> parsed = Host.parseHost(token);
			if (!parsed.isPresent()) {
				// Keywords such as 'self', 'unsafe-inline', or values the parse-time consumer already rejected.
				continue;
			}
			Host host = parsed.get();
			if (host.scheme == null) {
				// Relative sources are evaluated against the document origin and are not second-guessed.
				continue;
			}

			List<String> issues = pathIssues(host.path);
			if (!issues.isEmpty() || isDefaultPort(host)) {
				findings.add(buildHostFinding(policyIndex, directiveIndex, valueIndex, directiveName, token, host,
						issues, isDefaultPort(host)));
			}

			hostEntries.add(new HostEntry(valueIndex, token, host));
		}

		auditRedundancy(policyIndex, directiveIndex, directiveName, schemes, hostEntries, findings);
	}

	private static void auditRedundancy(int policyIndex, int directiveIndex, @Nonnull String directiveName,
			@Nonnull List<Scheme> schemes, @Nonnull List<HostEntry> hostEntries,
			@Nonnull List<AuditDiagnostic> findings) {
		for (int targetIndex = 0; targetIndex < hostEntries.size(); ++targetIndex) {
			HostEntry target = hostEntries.get(targetIndex);

			for (Scheme scheme : schemes) {
				if (Policy.schemePartMatches(scheme.value, target.host.scheme)) {
					findings.add(redundantFinding(policyIndex, directiveIndex, directiveName, target,
							"scheme-source " + scheme.toString()));
					break;
				}
			}
			if (findings.stream().anyMatch(f -> f.code.equals(AuditDiagnostic.REDUNDANT_SOURCE)
					&& f.directiveIndex == directiveIndex && f.valueIndex == target.valueIndex)) {
				continue;
			}

			// Equivalent sources only get flagged on their later occurrence, so that a pair produces exactly one finding.
			for (int otherIndex = 0; otherIndex < targetIndex; ++otherIndex) {
				if (hostsEquivalent(target.host, hostEntries.get(otherIndex).host)) {
					findings.add(redundantFinding(policyIndex, directiveIndex, directiveName, target,
							"host-source " + hostEntries.get(otherIndex).token));
					break;
				}
			}
			if (findings.stream().anyMatch(f -> f.code.equals(AuditDiagnostic.REDUNDANT_SOURCE)
					&& f.directiveIndex == directiveIndex && f.valueIndex == target.valueIndex)) {
				continue;
			}

			// A strict subsumption is only reported when the broader source appears first, which prevents two
			// sources which merely overlap (neither strictly contains the other) from flagging each other.
			for (int otherIndex = 0; otherIndex < targetIndex; ++otherIndex) {
				HostEntry other = hostEntries.get(otherIndex);
				if (!hostsEquivalent(target.host, other.host) && hostSubsumes(other.host, target.host)) {
					findings.add(redundantFinding(policyIndex, directiveIndex, directiveName, target,
							"host-source " + other.token));
					break;
				}
			}
		}
	}

	@Nonnull
	private static AuditDiagnostic redundantFinding(int policyIndex, int directiveIndex, @Nonnull String directiveName,
			@Nonnull HostEntry target, @Nonnull String subsumer) {
		return new AuditDiagnostic(
				AuditDiagnostic.REDUNDANT_SOURCE,
				Policy.Severity.Warning,
				policyIndex, directiveIndex, target.valueIndex, directiveName, target.token,
				"Host-source \"" + target.token + "\" is redundant: every request it allows is already allowed by " + subsumer,
				null);
	}

	@Nonnull
	private static AuditDiagnostic buildHostFinding(int policyIndex, int directiveIndex, int valueIndex,
			@Nonnull String directiveName, @Nonnull String token, @Nonnull Host host,
			@Nonnull List<String> pathIssues, boolean defaultPort) {
		StringBuilder message = new StringBuilder();
		message.append("Host-source \"").append(token).append("\" is written in a form which can diverge from real requests: ");
		List<String> reasons = new ArrayList<>();
		if (defaultPort) {
			reasons.add("port " + host.port + " is the default port of " + host.scheme + " and is implied when omitted");
		}
		reasons.addAll(pathIssues);
		message.append(String.join("; ", reasons));
		return new AuditDiagnostic(
				pathIssues.isEmpty() ? AuditDiagnostic.DEFAULT_PORT : AuditDiagnostic.PATH_NORMALIZATION,
				Policy.Severity.Warning,
				policyIndex, directiveIndex, valueIndex, directiveName, token,
				message.toString(),
				canonicalize(host));
	}

	// Reuses the exact match semantics of the querying path so audit findings describe real behavior.
	private static boolean hostSubsumes(@Nonnull Host subsumer, @Nonnull Host target) {
		if (!Policy.schemePartMatches(subsumer.scheme, target.scheme)) {
			return false;
		}
		if (!hostPartSubsumes(subsumer.host, target.host)) {
			return false;
		}
		if (!portSubsumes(subsumer.port, target.port, target.scheme)) {
			return false;
		}
		return pathSubsumes(subsumer.path, target.path);
	}

	private static boolean hostsEquivalent(@Nonnull Host a, @Nonnull Host b) {
		return Policy.schemePartMatches(a.scheme, b.scheme) && Policy.schemePartMatches(b.scheme, a.scheme)
				&& a.host.equals(b.host)
				&& a.port == b.port
				&& Objects.equals(a.path, b.path);
	}

	private static boolean hostPartSubsumes(@Nonnull String subsumer, @Nonnull String target) {
		if (subsumer.startsWith("*")) {
			return target.toLowerCase(Locale.ENGLISH).endsWith(subsumer.substring(1).toLowerCase(Locale.ENGLISH));
		}
		return subsumer.equals(target);
	}

	private static boolean portSubsumes(int subsumer, int target, @Nonnull String targetScheme) {
		if (subsumer == Constants.WILDCARD_PORT) {
			return true;
		}
		if (subsumer == Constants.EMPTY_PORT) {
			return target == Constants.EMPTY_PORT || target == URI.defaultPortForProtocol(targetScheme);
		}
		if (target == Constants.EMPTY_PORT) {
			return subsumer == URI.defaultPortForProtocol(targetScheme);
		}
		return subsumer == target;
	}

	private static boolean pathSubsumes(@Nullable String subsumer, @Nullable String target) {
		String a = subsumer == null ? "" : subsumer;
		String b = target == null ? "" : target;
		if (a.isEmpty()) {
			return true;
		}
		if (a.equals("/")) {
			return true;
		}
		List<String> segmentsA = Utils.strictlySplit(a, '/');
		List<String> segmentsB = Utils.strictlySplit(b, '/');
		if (a.endsWith("/")) {
			if (segmentsA.size() - 1 > segmentsB.size()) {
				return false;
			}
			for (int i = 0; i < segmentsA.size() - 1; ++i) {
				if (!segmentsA.get(i).equals(segmentsB.get(i))) {
					return false;
				}
			}
			return true;
		}
		if (segmentsA.size() != segmentsB.size()) {
			return false;
		}
		return segmentsA.equals(segmentsB);
	}

	private static boolean isDefaultPort(@Nonnull Host host) {
		return host.scheme != null && host.port != Constants.EMPTY_PORT && host.port != Constants.WILDCARD_PORT
				&& host.port == URI.defaultPortForProtocol(host.scheme);
	}

	@Nonnull
	private static List<String> pathIssues(@Nullable String path) {
		List<String> issues = new ArrayList<>();
		if (path == null) {
			return issues;
		}
		List<String> segments = Utils.strictlySplit(path, '/');
		// Host-source paths are always absolute (so the first element is empty by construction) and may end in
		// a slash (so the last element can also be empty); neither of those boundary empties is a "//".
		for (int i = 1; i < segments.size(); ++i) {
			if (segments.get(i).isEmpty() && i < segments.size() - 1) {
				issues.add("path contains an empty segment (\"//\"), which real URLs collapse");
				break;
			}
		}
		for (String segment : segments) {
			if (segment.equals(".") || segment.equals("..")) {
				issues.add("path contains a \"" + segment + "\" dot-segment, which real URLs resolve away");
				break;
			}
		}
		return issues;
	}

	// Suggestion produced without touching the original Host: re-render after dropping default ports
	// and resolving the path per https://tools.ietf.org/html/rfc3986#section-5.2.4.
	@Nonnull
	private static String canonicalize(@Nonnull Host host) {
		StringBuilder out = new StringBuilder();
		out.append(host.scheme).append("://").append(host.host);
		if (host.port != Constants.EMPTY_PORT && host.port != Constants.WILDCARD_PORT
				&& host.port != URI.defaultPortForProtocol(host.scheme)) {
			out.append(':').append(host.port);
		}
		if (host.path != null) {
			out.append(normalizePath(host.path));
		}
		return out.toString();
	}

	@Nonnull
	private static String normalizePath(@Nonnull String path) {
		boolean trailingSlash = path.endsWith("/");
		List<String> stack = new ArrayList<>();
		for (String segment : Utils.strictlySplit(path, '/')) {
			if (segment.isEmpty() || segment.equals(".")) {
				continue;
			}
			if (segment.equals("..")) {
				if (!stack.isEmpty()) {
					stack.remove(stack.size() - 1);
				}
				continue;
			}
			stack.add(segment);
		}
		StringBuilder out = new StringBuilder();
		for (String segment : stack) {
			out.append('/').append(segment);
		}
		if (out.length() == 0) {
			return "/";
		}
		if (trailingSlash && out.charAt(out.length() - 1) != '/') {
			out.append('/');
		}
		return out.toString();
	}

	private static final class HostEntry {
		final int valueIndex;
		@Nonnull
		final String token;
		@Nonnull
		final Host host;

		HostEntry(int valueIndex, @Nonnull String token, @Nonnull Host host) {
			this.valueIndex = valueIndex;
			this.token = token;
			this.host = host;
		}
	}
}
