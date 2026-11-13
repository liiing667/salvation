package com.shapesecurity.salvation2;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Objects;

// A single, explainable read-only finding produced by Policy#audit (or PolicyList#audit).
// An AuditDiagnostic never describes a mutation: the policy it was produced from is left
// untouched, and querying and serialization are unaffected.
public final class AuditDiagnostic {
	// Stable codes. These strings are part of the public API and must not be renamed.
	// The host-source explicitly writes the default port of its own scheme (e.g. http://example.com:80).
	public static final String DEFAULT_PORT = "host-default-port";
	// The host-source path contains double slashes or "."/".." segments, which do not survive URL resolution.
	public static final String PATH_NORMALIZATION = "host-path-normalization";
	// The source-expression is fully covered by another source-expression in the same directive.
	public static final String REDUNDANT_SOURCE = "redundant-source";
	// The source-expression can never match any request, for example because the directive also contains 'none'.
	public static final String UNREACHABLE_SOURCE = "unreachable-source";

	@Nonnull
	public final String code;
	@Nonnull
	public final Policy.Severity severity;
	// Index of the policy within a PolicyList, or -1 for an audit of a single Policy.
	public final int policyIndex;
	// Index of the directive within its policy, matching the indices reported by the parse-time error consumer.
	public final int directiveIndex;
	// Index of the value within its directive, matching the indices reported by the parse-time error consumer.
	public final int valueIndex;
	@Nonnull
	public final String directive;
	@Nonnull
	public final String value;
	@Nonnull
	public final String message;
	// A concrete normalization suggestion, or null when removal (or another manual change) is the only fix.
	@Nullable
	public final String suggestion;

	AuditDiagnostic(@Nonnull String code, @Nonnull Policy.Severity severity, int policyIndex, int directiveIndex,
			int valueIndex, @Nonnull String directive, @Nonnull String value, @Nonnull String message,
			@Nullable String suggestion) {
		this.code = code;
		this.severity = severity;
		this.policyIndex = policyIndex;
		this.directiveIndex = directiveIndex;
		this.valueIndex = valueIndex;
		this.directive = directive;
		this.value = value;
		this.message = message;
		this.suggestion = suggestion;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		AuditDiagnostic that = (AuditDiagnostic) o;
		return policyIndex == that.policyIndex &&
				directiveIndex == that.directiveIndex &&
				valueIndex == that.valueIndex &&
				code.equals(that.code) &&
				severity == that.severity &&
				directive.equals(that.directive) &&
				value.equals(that.value) &&
				message.equals(that.message) &&
				Objects.equals(suggestion, that.suggestion);
	}

	@Override
	public int hashCode() {
		return Objects.hash(code, severity, policyIndex, directiveIndex, valueIndex, directive, value, message, suggestion);
	}

	@Override
	public String toString() {
		return "AuditDiagnostic{" +
				"code='" + code + '\'' +
				", severity=" + severity +
				", policyIndex=" + policyIndex +
				", directiveIndex=" + directiveIndex +
				", valueIndex=" + valueIndex +
				", directive='" + directive + '\'' +
				", value='" + value + '\'' +
				", message='" + message + '\'' +
				", suggestion='" + suggestion + '\'' +
				'}';
	}
}
