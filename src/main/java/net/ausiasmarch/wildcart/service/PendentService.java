package net.ausiasmarch.wildcart.service;

import net.ausiasmarch.wildcart.entity.PendentEntity;
import net.ausiasmarch.wildcart.exception.ResourceNotFoundException;
import net.ausiasmarch.wildcart.repository.PendentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PendentService {

    @Autowired
    private PendentRepository oPendentRepository;

    private void validate(Long id) {
        if (!oPendentRepository.existsById(id)) {
            throw new ResourceNotFoundException("id " + id + " not exist");
        }
    }

    public PendentEntity get(Long id) {
        return oPendentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Pendent with id " + id + " not found"));
    }

    public Long count() {
        return oPendentRepository.count();
    }

    public PendentEntity create(PendentEntity oPendentEntity) {
        return oPendentRepository.save(oPendentEntity);
    }

    public Long update(PendentEntity oPendentEntity) {
        validate(oPendentEntity.getId());
        return oPendentRepository.save(oPendentEntity).getId();
    }

    public Long delete(Long id) {
        validate(id);
        oPendentRepository.deleteById(id);
        return id;
    }
}
