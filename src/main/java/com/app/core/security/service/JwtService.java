package com.app.core.security.service;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import com.app.core.entity.model.UserModel;

import java.util.Map;

public interface JwtService {

	public String extractUsernameFromToken(String jwt);
	public String getToken(Map<String, Object> extraClaims, UserModel userModel, long expiration);
	public String getToken(UserModel userModel);
	public String getRefreshToken(final UserModel userModel);
	public boolean isTokenValid(String token, UserDetails userDetails);
	Claims extractAllClaims(String token);

}
