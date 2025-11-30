package com.ippcda.auth.repository;

import java.util.UUID;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ippcda.auth.entity.User;

/**
 * Repository interface for User entity operations.
 * Existing operations that are inherited from JpaRepository:
 * - save(S entity)
 * - findById(ID id)
 * - deleteById(ID id)
 * - deleteAll()
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    Boolean existsByEmail(String email);
    Optional<User> findByEmail(String email);   
}
