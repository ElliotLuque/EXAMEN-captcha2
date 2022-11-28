/*
 * Copyright (c) 2021
 *
 * by Rafael Angel Aznar Aparici (rafaaznar at gmail dot com) & 2021 DAW students
 *
 * WILDCART: Free Open Source Shopping Site
 *
 * Sources at:                https://github.com/rafaelaznar/wildCartSBServer2021
 * Database at:               https://github.com/rafaelaznar/wildCartSBServer2021
 * POSTMAN API at:            https://github.com/rafaelaznar/wildCartSBServer2021
 * Client at:                 https://github.com/rafaelaznar/wildCartAngularClient2021
 *
 * WILDCART is distributed under the MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package net.ausiasmarch.wildcart.service;

import javax.servlet.http.HttpSession;
import javax.transaction.Transactional;

import net.ausiasmarch.wildcart.bean.CaptchaBean;
import net.ausiasmarch.wildcart.bean.TokenBean;
import net.ausiasmarch.wildcart.bean.UsuarioBean;
import net.ausiasmarch.wildcart.entity.PendentEntity;
import net.ausiasmarch.wildcart.entity.QuestionEntity;
import net.ausiasmarch.wildcart.exception.ResourceNotFoundException;
import net.ausiasmarch.wildcart.exception.UnauthorizedException;
import net.ausiasmarch.wildcart.entity.UsuarioEntity;
import net.ausiasmarch.wildcart.helper.RandomHelper;
import net.ausiasmarch.wildcart.helper.TipoUsuarioHelper;
import net.ausiasmarch.wildcart.repository.PendentRepository;
import net.ausiasmarch.wildcart.repository.QuestionRepository;
import net.ausiasmarch.wildcart.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuthService {

    @Autowired
    HttpSession oHttpSession;

    @Autowired
    UsuarioRepository oUsuarioRepository;

    @Autowired
    private QuestionRepository oQuestionRepository;

    @Autowired
    private PendentRepository oPendentRepository;

    @Value("${captcha.timeout}")
    private long captchaTimeout;

    @Transactional
    public TokenBean prelogin() {
        deleteExpiredPendents();

        PendentEntity oPendentEntity = new PendentEntity();

        List<QuestionEntity> allQuestions = oQuestionRepository.findAll();
        QuestionEntity randomQuestion = allQuestions.get(RandomHelper.getRandomInt(0, allQuestions.size() - 1));

        LocalDateTime timecode = LocalDateTime.now();
        oPendentEntity.setQuestion(randomQuestion);
        oPendentEntity.setTimecode(timecode);
        PendentEntity savedPendentEntity = oPendentRepository.save(oPendentEntity);

        // Token parameters for generation
        String timestamp = timecode.toString();
        String n1 = String.valueOf(randomQuestion.getId());
        String pendentEntityId = String.valueOf(savedPendentEntity.getId());
        String randomNumber = String.valueOf(RandomHelper.getRandomInt(1, 9999));

        String token = timestamp + n1 + pendentEntityId + randomNumber;
        String hashedToken = RandomHelper.getSHA256(token);

        savedPendentEntity.setToken(hashedToken);
        oPendentRepository.save(savedPendentEntity);

        TokenBean oTokenBean = new TokenBean();
        oTokenBean.setToken(hashedToken);
        oTokenBean.setStatement(savedPendentEntity.getQuestion().getStatement());

        return oTokenBean;
    }

    public UsuarioEntity loginC(@RequestBody CaptchaBean oCaptchaBean) {
        deleteExpiredPendents();

        if (oCaptchaBean.getPassword() != null) {
            UsuarioEntity oUsuarioEntity = oUsuarioRepository.findByLoginAndPassword(oCaptchaBean.getLogin(), oCaptchaBean.getPassword());
            if (oUsuarioEntity != null) {
                String token = oCaptchaBean.getToken();
                String captchaResponse = oCaptchaBean.getResponse();

                PendentEntity oPendentEntity = oPendentRepository.findByToken(token)
                        .orElseThrow(() -> new ResourceNotFoundException("Pendent with token " + token + " not found"));

                QuestionEntity oQuestionEntity = oPendentEntity.getQuestion();
                String answer = oQuestionEntity.getResponse();

                LocalDateTime requestTime = LocalDateTime.now();
                LocalDateTime timecode = oPendentEntity.getTimecode();

                if (requestTime.isAfter(timecode.plusSeconds(captchaTimeout))) {
                    throw new UnauthorizedException("Timecode expired");
                }

                if (answer.contains("|")) {
                    String[] answers = answer.split("\\|");
                    for (String a : answers) {
                        if (a.equals(captchaResponse)) {
                            oPendentRepository.delete(oPendentEntity);
                            oHttpSession.setAttribute("usuario", oUsuarioEntity);
                            return oUsuarioEntity;
                        }
                    }
                }

                if (answer.equals(captchaResponse)) {
                    oHttpSession.setAttribute("usuario", oUsuarioEntity);
                    oPendentRepository.delete(oPendentEntity);
                    return oUsuarioEntity;
                } else {
                    throw new UnauthorizedException("wrong captcha");
                }
            } else {
                throw new UnauthorizedException("login or password incorrect");
            }
        } else {
            throw new UnauthorizedException("wrong password");
        }
    }

    private void deleteExpiredPendents() {
        List<PendentEntity> allPendents = oPendentRepository.findAll();
        LocalDateTime now = LocalDateTime.now();

        allPendents.forEach((oPendentEntity) -> {
            if (oPendentEntity.getTimecode().plusSeconds(captchaTimeout).isBefore(now)) {
                oPendentRepository.delete(oPendentEntity);
            }
        });
    }

    public UsuarioEntity login(@RequestBody UsuarioBean oUsuarioBean) {
        if (oUsuarioBean.getPassword() != null) {
            UsuarioEntity oUsuarioEntity = oUsuarioRepository.findByLoginAndPassword(oUsuarioBean.getLogin(), oUsuarioBean.getPassword());
            if (oUsuarioEntity != null) {
                oHttpSession.setAttribute("usuario", oUsuarioEntity);
                return oUsuarioEntity;
            } else {
                throw new UnauthorizedException("login or password incorrect");
            }
        } else {
            throw new UnauthorizedException("wrong password");
        }
    }

    public void logout() {
        oHttpSession.invalidate();
    }

    public UsuarioEntity check() {
        UsuarioEntity oUsuarioSessionEntity = (UsuarioEntity) oHttpSession.getAttribute("usuario");
        if (oUsuarioSessionEntity != null) {
            return oUsuarioSessionEntity;
        } else {
            throw new UnauthorizedException("no active session");
        }
    }

    public boolean isLoggedIn() {
        UsuarioEntity oUsuarioSessionEntity = (UsuarioEntity) oHttpSession.getAttribute("usuario");
        if (oUsuarioSessionEntity == null) {
            return false;
        } else {
            return true;
        }
    }

    public Long getUserID() {
        UsuarioEntity oUsuarioSessionEntity = (UsuarioEntity) oHttpSession.getAttribute("usuario");
        if (oUsuarioSessionEntity != null) {
            return oUsuarioSessionEntity.getId();
        } else {
            throw new UnauthorizedException("this request is only allowed to auth users");
        }
    }

    public boolean isAdmin() {
        UsuarioEntity oUsuarioSessionEntity = (UsuarioEntity) oHttpSession.getAttribute("usuario");
        if (oUsuarioSessionEntity != null) {
            if (oUsuarioSessionEntity.getTipousuario().getId().equals(TipoUsuarioHelper.ADMIN)) {
                return true;
            }
        }
        return false;
    }

    public boolean isUser() {
        UsuarioEntity oUsuarioSessionEntity = (UsuarioEntity) oHttpSession.getAttribute("usuario");
        if (oUsuarioSessionEntity != null) {
            if (oUsuarioSessionEntity.getTipousuario().getId().equals(TipoUsuarioHelper.USER)) {
                return true;
            }
        }
        return false;
    }

    public void OnlyAdmins() {
        UsuarioEntity oUsuarioSessionEntity = (UsuarioEntity) oHttpSession.getAttribute("usuario");
        if (oUsuarioSessionEntity == null) {
            throw new UnauthorizedException("this request is only allowed to admin role");
        } else {
            if (!oUsuarioSessionEntity.getTipousuario().getId().equals(TipoUsuarioHelper.ADMIN)) {
                throw new UnauthorizedException("this request is only allowed to admin role");
            }
        }
    }

    public void OnlyUsers() {
        UsuarioEntity oUsuarioSessionEntity = (UsuarioEntity) oHttpSession.getAttribute("usuario");
        if (oUsuarioSessionEntity == null) {
            throw new UnauthorizedException("this request is only allowed to user role");
        } else {
            if (!oUsuarioSessionEntity.getTipousuario().getId().equals(TipoUsuarioHelper.USER)) {
                throw new UnauthorizedException("this request is only allowed to user role");
            }
        }
    }

    public void OnlyAdminsOrUsers() {
        UsuarioEntity oUsuarioSessionEntity = (UsuarioEntity) oHttpSession.getAttribute("usuario");
        if (oUsuarioSessionEntity == null) {
            throw new UnauthorizedException("this request is only allowed to user or admin role");
        } else {

        }
    }

    public void OnlyAdminsOrOwnUsersData(Long id) {
        UsuarioEntity oUsuarioSessionEntity = (UsuarioEntity) oHttpSession.getAttribute("usuario");
        if (oUsuarioSessionEntity != null) {
            if (oUsuarioSessionEntity.getTipousuario().getId().equals(TipoUsuarioHelper.USER)) {
                if (!oUsuarioSessionEntity.getId().equals(id)) {
                    throw new UnauthorizedException("this request is only allowed for your own data");
                }
            }
        } else {
            throw new UnauthorizedException("this request is only allowed to user or admin role");
        }
    }

}
