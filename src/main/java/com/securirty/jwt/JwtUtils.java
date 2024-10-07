package com.securirty.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtils {

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;


    private Logger logger = LoggerFactory.getLogger(JwtUtils.class);


    public String getJwtFromHeader(HttpServletRequest request) {

        String bearerTokan = request.getHeader("Authorization");

        logger.debug("Authorization Header :{} ", bearerTokan);

        if (bearerTokan != null && bearerTokan.startsWith("Bearer ")) {
            return bearerTokan.substring(7);
        }
        return null;
    }

    public String generateTokenFromUserName(UserDetails userDetails) {
        String username = userDetails.getUsername();

        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(key())
                .compact();

    }

    public String getUserNameFromJwtToken(String token) {


        return Jwts.parser().verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();

    }

    public boolean validiateToken(String authToken) {

        try {
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.debug("Jwt authToken is malformed");
        } catch (ExpiredJwtException e) {
            logger.debug("Jwt authToken is expired");
        } catch (UnsupportedJwtException e) {
            logger.debug("Jwt authToken is unsupported");
        } catch (IllegalArgumentException e) {
            logger.debug("Jwt authToken Illegal argument exception");
        }
        return false;


    }


    private Key key() {

//        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
//        return Keys.hmacShaKeyFor(keyBytes);
       // return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));

        return Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);

    }

    public Key keyFromBytes() {
        byte[] keyBytes = new byte[32];  // 256 bits = 32 bytes
        // Ensure keyBytes are securely generated or use a predefined secure key
        return Keys.hmacShaKeyFor(keyBytes);
    }




}
