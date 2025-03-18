<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

//must notice

class AuthController extends Controller
{
    public function user()
    {
        return Auth::user();
    }

    public function register(Request $request)
    {

//        ------------------------------------------------- validation block -------------------------------------------------


        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required',
                'name' => 'required',
                'password' => 'required',
            ]);

            if ($validator->fails()) {
                throw new ValidationException($validator);
            }

            $inputs = $validator->validated();

//        ------------------------------------------------- validation block -------------------------------------------------

//        -------------------------------- Rest of the codes --------------------------------


            // Check if the email already exists in the database

            if (User::where('email', $inputs['email'])->exists()) {
                return response([
                    'message' => 'Email already exists'
                ], Response::HTTP_BAD_REQUEST);
            }

            $user = User::create([
                'name' => $inputs['name'],
                'email' => $inputs['email'],
                'password' => Hash::make($inputs['password'])
            ]);

            if (Auth::attempt(['email' => $request->input('email'), 'password' => $request->input('password')])) {
                $user = Auth::user();
                $token = $user->createToken('token')->plainTextToken;
                $cookie = cookie('jwt', $token, 60 * 24 * 30); // 30 days


                return response([
                    'token' => $token,
                    'user' => $user,
                    'status' => Response::HTTP_OK,
                    'message' => 'Register successfully'
                ])->withCookie($cookie);


            }

            return response([
                'message' => 'Invalid Credentials',
                'status' => Response::HTTP_UNAUTHORIZED
            ], Response::HTTP_UNAUTHORIZED);

//        -------------------------------- Rest of the codes --------------------------------


//        ------------------------------------------------- validation block -------------------------------------------------


        } catch (ValidationException $e) {
            return response()->json(['error' => $e->validator->errors()], 422);
        }


//        ------------------------------------------------- validation block -------------------------------------------------

    }

    public function login(Request $request)
    {

        //        ------------------------------------------------- validation block -------------------------------------------------


        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required',
                'password' => 'required',
            ]);

            if ($validator->fails()) {
                throw new ValidationException($validator);
            }

            $inputs = $validator->validated();

            //        ------------------------------------------------- validation block -------------------------------------------------


            if (!Auth::attempt($request->only('email', 'password'))) {
                return response([
                    'message' => 'Invalid Credentials'
                ], Response::HTTP_UNAUTHORIZED);
            };
            $user = Auth::user();
            $token = $user->createToken('token')->plainTextToken;
            $cookie = cookie('jwt', $token, 60 * 24 * 30); //30days
            return response([
                'token' => $token,
                'user' => $user,
                'status' => Response::HTTP_OK,
            ])->withCookie($cookie);

            //        ------------------------------------------------- validation block -------------------------------------------------


        } catch (ValidationException $e) {
            return response()->json(['error' => $e->validator->errors()], 422);
        }


        //        ------------------------------------------------- validation block -------------------------------------------------

    }


    public function logout(Request $request)
    {

        $token = $request->bearerToken();

        // Revoke the specific token
        $user = Auth::user();
        $user->tokens()->where('id', explode('|', $token)[0])->delete();

        $cookie = Cookie::forget('jwt');

        return response([
            'message' => 'successfully logged out'
        ])->withCookie($cookie);
    }

    public function logout_all_devices()
    {
        $user = Auth::user();
        $user->tokens()->delete(); // Delete all tokens for the user

        $cookie = Cookie::forget('jwt');

        return response([
            'message' => 'successfully logged out'
        ])->withCookie($cookie);
    }
}
