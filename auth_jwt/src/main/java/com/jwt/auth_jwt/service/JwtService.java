package com.jwt.auth_jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    // Extraire le nom d'utilisateur à partir du token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // methode pour extraire les informations specifiques dans le token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Générer un token simple sans claims
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // Générer un token avec claims
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    // retourne l'expiration du jwt
    public long getExpirationTime() {
        return jwtExpiration;
    }

    // methode pour construire un jwt complet
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims) // ajout de données personnalisées
                .setSubject(userDetails.getUsername()) // nom d'utilisateur
                .setIssuedAt(new Date(System.currentTimeMillis())) // date d'emission du token
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // date d'expiration du token
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // la signature du token
                .compact(); // géneration de la chaine finale jwt
    }

    // methode pour vérifier la validiter du token ( username + date d'expiration du token )
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // methode pour verifier si le token est expirer
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // methode pour extraire la date d'expiration du token
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // methode pour extraire toutes les information contenues dans le token
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) // la clé utiliser pour
                .build()
                .parseClaimsJws(token) // lecture du jwt signé
                .getBody(); // return claims ( le corp )
    }

    // Transforme la clé Base64 en clé cryptographique utilisable ( hachage de clé base64 )
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}

