package com.usuario.config;

import java.security.Key;
import java.util.Date;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;


/* QUE ES UN TOCKEN: UNIDAD DIGITAL QUE REPRESENTA INFORMACIÓN, O UNA CREDENCIAL DE ACCESO
 * CILO DE VIDA DE UN TOCKEN: 
 * donde guardas lo tockens?
 * que es una key?
 * puedes guardas un tocken en memoria?
 * 
 * 
 * */
@Component
public class JwtUtils {
	// CLAVE SECRETA(TOCKEN) DE 32 CARACTERES - 252 BITS
	// PASSWORD: SECRET_PASSWORD
	private static final String SECRET_KEY="$2a$10$SiRrYuRZC9w/.sU9XahX3e10EmXNAijfEv7nAdkjFnpNcIKFM3h6y";
	
	//TIEMPO DE EXPIRACION DE 1 HORA
	private static final long EXPIRATION_TIME=3600000;
	
	private final Key key= Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
	
	// GENERA TOKEN - JWT JWSON WEB TOCKEN
	public String generarTocken(String username,String role) {
		return Jwts
				.builder()
				.setSubject(username)
				.claim("role", role)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.signWith(key,SignatureAlgorithm.HS256)
				.compact();
	}
}
