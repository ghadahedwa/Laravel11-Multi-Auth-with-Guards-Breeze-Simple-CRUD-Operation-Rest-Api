<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use function Carbon\first;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules;


class AuthController extends Controller
{
    public function login(Request $request):JsonResponse{
        $request->validate([
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255'],
            'password' => ['required', 'string','min:8', 'max:255'],
        ]);

        $user = User::where('email' ,$request->email)->first();

        if(!$user || ! Hash::check($request->password,$user->password)){
            return response()->json([
                'message'=>'The provieded credentails are incorrect'
            ],401);
        }

        $token=$user->createToken($user->name,['server:Auth-Token'])->plainTextToken;

        return response()->json([
            'message'=>'Login Successfuly',
            'token_type'=>'Bearer',
            'token'=>$token
        ],200);

    }

    public function register(Request $request){
        $request->validate([
            'name' =>'required|string|max:255',
            //'email' => 'required|string|lowercase|email|unique:users,email|max:255',
            'password' => 'required|string|min:8|max:255',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        if($user){

            $token=$user->createToken($user->name,['server:Auth-Token'])->plainTextToken;

            return response()->json([
                'message'=>'Registeration Successful',
                'token_type'=>'Bearer',
                'token'=>$token
            ],201);
        }
        else{
            return response()->json([
                'message'=>'something went wrong!',
            ],500);
        }
    }

    public function profile(Request $request){

        if($request->user()){

            return response()->json([
                'message'=>'Profile Successful',
                'data'=>$request->user()
            ],200);
        }
        else{
            return response()->json([
                'message'=>'something went wrong!',
            ],500);
        }
    }

    public function logout(Request $request){
        $user = User::where('id' ,$request->user()->id)->first();
        if($user){
            $user->tokens()->delete();
            return response()->json([
                'message'=>'logout Successful',
            ],200);
        }
        else{
            return response()->json([
                'message'=>'something went wrong!',
            ],404);
        }
    }
}
