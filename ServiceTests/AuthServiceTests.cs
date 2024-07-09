﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Moq;
using TestWebAPI.Repositories.Interfaces;
using AutoMapper;
using TestWebAPI.Services;
using TestWebAPI.Models;
using TestWebAPI.DTOs.Auth;
using TestWebAPI.Services.Interfaces;
using Microsoft.AspNetCore.Http;
using TestWebAPI.Middlewares;
using TestWebAPI.Helpers;
using TestWebAPI.Helpers.IHelpers;
using TestWebAPI.DTOs.JWT;

namespace XUnitTestWebAPI.ServiceTests
{
    public class AuthServiceTests
    {
        private readonly Mock<IAuthRepositories> _authRepoMock;
        private readonly Mock<IRoleRepositories> _roleRepoMock;
        private readonly Mock<IJWTHelper> _jwtHelperMock;
        private readonly Mock<IJwtServices> _jwtServiceMock;
        private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock;
        private readonly Mock<IUserRepositories> _userRepoMock;
        private readonly Mock<IHashPasswordHelper> _hashPasswordHelper;
        private readonly IMapper _mapper;
        private readonly AuthServices _authServices;

        public AuthServiceTests()
        {
            _authRepoMock = new Mock<IAuthRepositories>();
            _roleRepoMock = new Mock<IRoleRepositories>();
            _jwtHelperMock = new Mock<IJWTHelper>();
            _jwtServiceMock = new Mock<IJwtServices>();
            _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
            _userRepoMock = new Mock<IUserRepositories>();
            _hashPasswordHelper = new Mock<IHashPasswordHelper>();

            var config = new MapperConfiguration(cfg =>
            {
                cfg.CreateMap<AuthRegisterDTO, User>();
                cfg.CreateMap<User, AuthRegisterDTO>();
            });
            _mapper = config.CreateMapper();

            _authServices = new AuthServices(
                _mapper,
                _authRepoMock.Object,
                _jwtHelperMock.Object,
                _jwtServiceMock.Object,
                _httpContextAccessorMock.Object,
                _userRepoMock.Object,
                _roleRepoMock.Object,
                _hashPasswordHelper.Object
            );
        }
        [Fact]
        public async Task Register_EmailAlreadyExists_ReturnError()
        {
            // Arrange
            var authRegisterDTO = new AuthRegisterDTO { email = "Jorge_Turcotte@gmail.com", password = "stringst", roleCode = "D22MD2", first_name = "Test", last_name = "test" };
            _authRepoMock.Setup(repo => repo.getByEmail(authRegisterDTO.email)).ReturnsAsync(new User { first_name = authRegisterDTO.first_name, last_name = authRegisterDTO.last_name, email = authRegisterDTO.email, password = authRegisterDTO.password, roleCode = authRegisterDTO.roleCode });

            // Act
            var result = await _authServices.Register(authRegisterDTO);

            // Assert
            Assert.False(result.success);
            Assert.Equal("Email already exists!", result.message);
        }

        [Fact]
        public async Task Register_RoleNotFound_ReturnError()
        {
            // Arrange
            var authRegisterDTO = new AuthRegisterDTO { email = "test@example.com", password = "stringst", roleCode = "invalidRole", first_name = "Test", last_name = "test" };
            _authRepoMock.Setup(repo => repo.getByEmail(authRegisterDTO.email)).ReturnsAsync((User)null);
            _roleRepoMock.Setup(repo => repo.GetRoleByCodeAsyn(authRegisterDTO.roleCode)).ReturnsAsync((Role)null);

            // Act
            var result = await _authServices.Register(authRegisterDTO);

            // Assert
            Assert.False(result.success);
            Assert.Equal("Role not found!", result.message);
        }

        [Fact]
        public async Task Register_Success_ReturnSuccess()
        {
            // Arrange
            var authRegisterDTO = new AuthRegisterDTO { email = "hohuy12344@gmail.com", password = "stringst", roleCode = "D22MD2", first_name = "Test", last_name = "test" };
            _authRepoMock.Setup(repo => repo.getByEmail(authRegisterDTO.email)).ReturnsAsync((User)null);
            _roleRepoMock.Setup(repo => repo.GetRoleByCodeAsyn(authRegisterDTO.roleCode)).ReturnsAsync(new Role { value = "Admin", code = authRegisterDTO.roleCode });
            _authRepoMock.Setup(repo => repo.Register(It.IsAny<User>())).ReturnsAsync(new User { first_name = authRegisterDTO.first_name, last_name = authRegisterDTO.last_name, email = authRegisterDTO.email, password = authRegisterDTO.password, roleCode = authRegisterDTO.roleCode });

            // Act
            var result = await _authServices.Register(authRegisterDTO);

            // Assert
            Assert.True(result.success);
            Assert.Equal("Register successfully!", result.message);
        }
        [Fact]
        public async Task Login_EmailNotFound_ReturnError()
        {
            // Arrange
            var authLoginDTO = new AuthLoginDTO { email = "hohuy12344@gmail.com" };
            _authRepoMock.Setup(repo => repo.getByEmail(authLoginDTO.email)).ReturnsAsync((User)null);

            // Act
            var result = await _authServices.Login(authLoginDTO);

            // Assert
            Assert.False(result.success);
            Assert.Equal("Email not found!", result.message);

        }

        [Fact]
        public async Task Login_PasswordUnauthorized_ReturnsError()
        {
            // Assert
            var existingEmail = new User { email = "hohuy12344@gmail.com", password = "stringst", first_name = "string", last_name = "string", roleCode = "D22MD2" };
            var authLoginDTO = new AuthLoginDTO { email = "hohuy12344@gmail.com", password = "wrong_password" };

            _authRepoMock.Setup(repo => repo.getByEmail(authLoginDTO.email)).ReturnsAsync(existingEmail);
            _hashPasswordHelper.Setup(helper => helper.VerifyPassword(authLoginDTO.password, existingEmail.password)).Returns(false);

            // Act
            var result = await _authServices.Login(authLoginDTO);

            // Assert
            Assert.False(result.success);
            Assert.Equal("Password is wrong!", result.message);
        }

        [Fact]
        public async Task Login_Success_ReturnToken()
        {
            // Assert
            var existingEmail = new User { email = "hohuy12344@gmail.com", password = "stringst", first_name = "string", last_name = "string", roleCode = "D22MD2" };
            var authLoginDTO = new AuthLoginDTO { email = "hohuy12344@gmail.com", password = "stringst" };

            _authRepoMock.Setup(repo => repo.getByEmail(authLoginDTO.email)).ReturnsAsync(existingEmail);
            _hashPasswordHelper.Setup(helper => helper.VerifyPassword(authLoginDTO.password, existingEmail.password)).Returns(true);
            _jwtHelperMock.Setup(jwt => jwt.GenerateJWTToken(existingEmail.id, existingEmail.roleCode, It.IsAny<DateTime>())).ReturnsAsync("fake_jwt_token");
            _jwtHelperMock.Setup(jwt => jwt.GenerateJWTRefreshToken(existingEmail.id, existingEmail.roleCode, It.IsAny<DateTime>())).ReturnsAsync("fake_refresh_token");
            _jwtServiceMock.Setup(service => service.InsertJWTToken(It.IsAny<jwtDTO>())).Returns(Task.CompletedTask);

            var mockHttpContext = new DefaultHttpContext();
            _httpContextAccessorMock.Setup(_ => _.HttpContext).Returns(mockHttpContext);

            // Act
            var result = await _authServices.Login(authLoginDTO);

            // Assert
            Assert.True(result.success);
            Assert.Equal("Login successfully!", result.message);
            Assert.NotNull(result.accessToken);
            Assert.Equal("fake_jwt_token", result.accessToken);

            // Verify cookie was set
            var setCookieHeader = mockHttpContext.Response.Headers["Set-Cookie"].ToString();
            Assert.Contains("refresh_token", setCookieHeader);
            Assert.Contains("fake_refresh_token", setCookieHeader);
        }
    }
}