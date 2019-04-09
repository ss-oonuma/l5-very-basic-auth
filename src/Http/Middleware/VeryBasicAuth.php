<?php namespace Olssonm\VeryBasicAuth\Http\Middleware;

use Closure;
use App\AdminUserBasicAuths;

class VeryBasicAuth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        // Check if middleware is in use in current environment
        if(count(array_intersect(['*', app()->environment()], config('very_basic_auth.envs'))) > 0) {
            // XXX:maybe more elegant code
            $flag=false;
            $special_companys=AdminUserBasicAuths::where("auth_type","1")->get();
            foreach($special_companys as $special_company){
                $id=$special_company->basic_auth_id;
                $password=$special_company->basic_password;
                if( $request->getUser() == $id && Hash::check($request->getPassword(), $password) ) {
                    //正常なユーザー
                    $flag = true;
                }
            }
            if($flag == false){
                //id or passwordが間違っている
                $header = ['WWW-Authenticate' => sprintf('Basic realm="%s", charset="UTF-8"', config('very_basic_auth.realm', 'Basic Auth'))];

                // If the request want's JSON
                if ($request->wantsJson()) {
                    return response()->json([
                        'message' => config('very_basic_auth.error_message')
                    ], 401, $header);
                }

                // If view is available
                $view = config('very_basic_auth.error_view');
                if (isset($view)) {
                    return response()->view($view, [], 401)
                        ->withHeaders($header);
                }

                // Else return default message
                return response(config('very_basic_auth.error_message'), 401, $header);
            }
        }

        return $next($request);
    }
}
