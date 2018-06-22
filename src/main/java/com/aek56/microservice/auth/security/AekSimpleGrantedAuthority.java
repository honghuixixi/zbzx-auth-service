package com.aek56.microservice.auth.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

public class AekSimpleGrantedAuthority implements GrantedAuthority{

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String role;
	private final Integer dataScope;

	public AekSimpleGrantedAuthority(String role,Integer dataScope) {
		Assert.hasText(role, "A granted authority textual representation is required");
		this.role = role;
		this.dataScope = dataScope;
	}

	public String getAuthority() {
		return role;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AekSimpleGrantedAuthority other = (AekSimpleGrantedAuthority) obj;
		if (dataScope == null) {
			if (other.dataScope != null)
				return false;
		} else if (!dataScope.equals(other.dataScope))
			return false;
		if (role == null) {
			if (other.role != null)
				return false;
		} else if (!role.equals(other.role))
			return false;
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((dataScope == null) ? 0 : dataScope.hashCode());
		result = prime * result + ((role == null) ? 0 : role.hashCode());
		return result;
	}

	@Override
	public String toString() {
		return "AekSimpleGrantedAuthority [role=" + role + ", dataScope=" + dataScope + "]";
	}
	
}
