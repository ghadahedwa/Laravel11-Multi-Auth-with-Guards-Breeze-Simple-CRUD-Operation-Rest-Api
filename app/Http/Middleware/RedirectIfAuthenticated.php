<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpFoundation\Response;

class RedirectIfAuthenticated
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, ...$guards): Response
    {
        //dd($guards);
        $guards=empty($guards)?[null]:$guards;
        foreach ($guards as $guard){
            #Check if guard is authenticated
            if(Auth::guard($guard)->check()){
                if($guard==='admin'&&Route::is('admin.*'))
                    return redirect()->route('admin.dashboard');
                elseif ($guard==='superadmin'&&Route::is('superadmin.*'))
                    return redirect()->route('superadmin.dashboard');
                else
                    return redirect()->route('dashboard');
            }
        }
        return $next($request);
    }
}
