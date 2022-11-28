package net.ausiasmarch.wildcart.service;

import net.ausiasmarch.wildcart.entity.QuestionEntity;
import net.ausiasmarch.wildcart.exception.ResourceNotFoundException;
import net.ausiasmarch.wildcart.repository.QuestionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class QuestionService {

    @Autowired
    private QuestionRepository oQuestionRepository;

    private void validate(Long id) {
        if (!oQuestionRepository.existsById(id)) {
            throw new ResourceNotFoundException("id " + id + " not exist");
        }
    }

    public QuestionEntity get(Long id) {
        return oQuestionRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Question with id " + id + " not found"));
    }

    public Long count() {
        return oQuestionRepository.count();
    }

    public QuestionEntity create(QuestionEntity oQuestionEntity) {
        return oQuestionRepository.save(oQuestionEntity);
    }

    public Long update(QuestionEntity oQuestionEntity) {
        validate(oQuestionEntity.getId());
        return oQuestionRepository.save(oQuestionEntity).getId();
    }

    public Long delete(Long id) {
        validate(id);
        oQuestionRepository.deleteById(id);
        return id;
    }
}
