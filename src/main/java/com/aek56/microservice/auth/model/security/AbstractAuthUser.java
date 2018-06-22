package com.aek56.microservice.auth.model.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Security User
 *
 * @author zj@aek56.com
 */
public abstract class AbstractAuthUser implements UserDetails {

	private static final long serialVersionUID = 1L;

	@JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

}
