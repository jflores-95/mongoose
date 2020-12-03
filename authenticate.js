var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var User = require('./models/user');
var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken');
const config = require('./config');

exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = function(user){
    return jwt.sign(user, config.secretKey, 
        {expiresIn: 3600});
};

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(new JwtStrategy(opts, 
    (jwt_payload, done) => {
        console.log("JWT payload: ", jwt_payload);
        User.findOne({_id: jwt_payload._id}, (err, user) => {
            if(err){
                return done(err, false);
            } else if(user) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        });
    }));

exports.verifyUser = passport.authenticate('jwt', {session: false});

exports.verifyAdmin = (req,res,next) => {
    passport.authenticate('jwt', {session: false}, (err,user,info) => {
      console.log("verifyAdmin starts");
      //si hubo un error relacionado con la validez del token (error en su firma, caducado, etc)
      if(info){ 
        var err = new Error(info.message);
        err.status = 401;
        return next(err);
      }
      //si hubo un error en la consulta a la base de datos
      if (err) { 
          return next(err); 
      }
      //si el token está firmado correctamente pero no pertenece a un usuario existente
      if (!user) { 
        var err = new Error('You are not authorized to perform this operation!');
        err.status = 403;
        return next(err);
      }
      
      //si el usuario es un admin
      if(user.admin){
        req.user = user;
        next();
      }else{
        var err = new Error('You are not authorized to perform this operation!');
        err.status = 403;
        return next(err);
      }
    })(req,res,next);
};