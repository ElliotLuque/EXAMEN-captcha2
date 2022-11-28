package net.ausiasmarch.wildcart.repository;

import net.ausiasmarch.wildcart.entity.PendentEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PendentRepository extends JpaRepository<PendentEntity, Long> {

    Optional<PendentEntity> findByToken(String token);
}

