package net.ausiasmarch.wildcart.repository;

import net.ausiasmarch.wildcart.entity.TipoUsuarioEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TipousuarioRepository extends JpaRepository<TipoUsuarioEntity, Long> {

    public Page<TipoUsuarioEntity> findByNombreIgnoreCaseContaining(String strFilter, Pageable oPageable);

}
