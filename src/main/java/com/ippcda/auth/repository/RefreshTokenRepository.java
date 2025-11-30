package com.ippcda.auth.repository;

import java.util.UUID;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ippcda.auth.entity.RefreshToken;

/**
 * Repository interface for RefreshToken entity operations.
 * Existing operations that are inherited from JpaRepository:
 * - save(S entity)
 * - delete(RefreshToken entity)
 * - deleteAll()
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHash(String token);    
}
