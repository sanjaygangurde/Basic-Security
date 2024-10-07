package com.securirty.jwt;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import javax.websocket.Decoder;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtils {

    @Value("$spring.app.jwtExpirationMs")
    private int jwtExpirationMs;

    @Value("$spring.app.jwtSecret")
    private String jwtSecret;

    private Logger logger= LoggerFactory.getLogger(JwtUtils.class);


    public String getJwtFromHeader(HttpServletRequest request){

       String bearerTokan= request.getHeader("Authorization");

       logger.debug("Authorization Header :{} ",bearerTokan);

       if(bearerTokan !=null && bearerTokan.startsWith("Bearer "))
       {
           return bearerTokan.substring(7);
       }
       return null;
    }

    public String generateTokenFromUserName(UserDetails userDetails)
    {
        String username = userDetails.getUsername();

        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+jwtExpirationMs))
                .signWith(key())
                .compact();

    }

    public String getUserNameFromJwtToken(String token , SecretKey secretKey){

        return Jwts.parser().verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();

    }

    public boolean validiateToken(String authToken ,SecretKey secretKey){

        try {
            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        }catch (Exception e){
           logger.debug("Jwt authToken is not valid");
        }
        return false;


    }



    private Key key()
    {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }



}
