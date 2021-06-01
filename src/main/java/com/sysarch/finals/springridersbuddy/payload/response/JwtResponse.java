package com.sysarch.finals.springridersbuddy.payload.response;

import java.util.List;

public class JwtResponse {
	private String token;
	private String type = "Bearer";
	private String id;
	private String firstname;
	private String lastname;
	private String mi;
	private String username;
	private String email;
	private List<String> roles;

	public JwtResponse(String accessToken, String id, String firstname, String lastname, String mi, String username, String email, List<String> roles) {
		this.token = accessToken;
		this.id = id;
		this.firstname = firstname;
		this.lastname = lastname;
		this.mi = mi;
		this.username = username;
		this.email = email;
		this.roles = roles;
	}

	public String getAccessToken() {
		return token;
	}

	public void setAccessToken(String accessToken) {
		this.token = accessToken;
	}

	public String getTokenType() {
		return type;
	}

	public void setTokenType(String tokenType) {
		this.type = tokenType;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getFirstname() {
        return this.firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return this.lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getMi() {
        return this.mi;
    }

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public List<String> getRoles() {
		return roles;
	}
}
