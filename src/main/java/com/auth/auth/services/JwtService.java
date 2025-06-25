package com.auth.auth.services;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import javax.management.RuntimeErrorException;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.auth.auth.component.JwtProperties;
import com.auth.auth.entities.Authentication;
import com.auth.auth.utils.GenerateKeyUtil;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {

	private final JwtProperties jwtProperties;

	private final PrivateKey privateKey;

	private final PublicKey publicKey;

	public JwtService(JwtProperties jwtProperties) throws NoSuchAlgorithmException {
		this.jwtProperties = jwtProperties;
		GenerateKeyUtil keyUtil = new GenerateKeyUtil(); // ใช้ key ใหม่ทุกครั้ง (ใช้เฉพาะ dev/test)
		this.privateKey = keyUtil.getPrivateKey();
		this.publicKey = keyUtil.getPublicKey();
	}

	public String generateToken(Authentication auth) {
		return Jwts.builder()
				.setSubject(auth.getUsername())
				.setIssuedAt(new Date())
				.setExpiration(Date.from(Instant.now().plus(3, ChronoUnit.MINUTES)))
				.signWith(privateKey, SignatureAlgorithm.RS256)
				.compact();
	}

	public String extractUsername(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(jwtProperties.getSecret().getBytes())
				.build()
				.parseClaimsJws(token)
				.getBody().getSubject();
	}

	public boolean isTokenValid(String token, UserDetails userDetails) {
		return extractUsername(token).equals(userDetails.getUsername());
	}

	public boolean isTokenValid(String accessToken) {
		return extractUsername(accessToken).equals("admin");
	}

	private PrivateKey loadPrivateKey(String key) {
		try {
			byte[] keyBytes = Base64.getDecoder().decode(key);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			return KeyFactory.getInstance("RSA").generatePrivate(spec);
		} catch (Exception e) {
			throw new RuntimeException("Failed to load private key", e);
		}
	}

	private PublicKey loadPublicKey(String key) {
		try {
			byte[] keyBytes = Base64.getDecoder().decode(key);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			return KeyFactory.getInstance("RSA").generatePublic(spec);
		} catch (Exception e) {
			throw new RuntimeException("Failed to load public key", e);
		}
	}

}
