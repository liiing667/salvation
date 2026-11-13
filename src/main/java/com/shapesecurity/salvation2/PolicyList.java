package com.shapesecurity.salvation2;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PolicyList {
	public final List<Policy> policies;

	public PolicyList(List<Policy> policies) {
		this.policies = policies;
	}

	// Read-only audit of every policy; diagnostic policyIndex values index into this PolicyList.
	@Nonnull
	public List<AuditDiagnostic> audit() {
		List<AuditDiagnostic> findings = new ArrayList<>();
		for (int policyIndex = 0; policyIndex < this.policies.size(); ++policyIndex) {
			findings.addAll(PolicyAuditor.audit(this.policies.get(policyIndex), policyIndex));
		}
		return Collections.unmodifiableList(findings);
	}

	@Override
	public String toString() {
		StringBuilder out = new StringBuilder();
		boolean first = true;
		for (Policy policy : this.policies) {
			if (!first) {
				out.append(", "); // The whitespace is not strictly necessary but is probably valuable
			}
			first = false;
			out.append(policy.toString());
		}
		return out.toString();
	}
}
