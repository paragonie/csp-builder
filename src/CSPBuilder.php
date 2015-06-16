<?php
namespace ParagonIE\CSPBuilder;

class CSPBuilder
{
    const FORMAT_APACHE = 'apache';
    const FORMAT_NGINX = 'nginx';
    
    private $policies = [];
    private $needsCompile = true;
    private $compiled = '';
    private $reportOnly = false;
    
    private static $directives = [
        'base-uri',
        'default-src',
        'child-src',
        'connect-uri',
        'font-uri',
        'form-action',
        'frame-ancestors',
        'img-src',
        'media-src',
        'object-src',
        'script-src',
        'style-src'
    ];
    
    /**
     * @param array $policy
     */
    public function __construct(array $policy = [])
    {
        $this->policies = $policy;
    }
    
    /**
     * Compile the current policies into a CSP header
     * 
     * @return string
     */
    public function compile()
    {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array('report-only', $ruleKeys)) {
            $this->reportOnly = !!$this->policies['report-only'];
        } else {
            $this->reportOnly = false;
        }
        
        $compiled = [];
        
        foreach(self::$directives as $dir) {
            if (\in_array($dir, $ruleKeys)) {
                $compiled []= $this->compileSubgroup(
                    $dir,
                    $this->policies[$dir]
                );
            }
        }
        
        if (!empty($this->policies['report-uri'])) {
            $compiled []= 'report-uri '.$this->policies['report-uri'].'; ';
        }
        if (!empty($this->policies['upgrade-insecure-requests'])) {
            $compiled []= 'upgrade-insecure-requests';
        }
        
        $this->compiled = \implode('', $compiled);
        $this->needsCompile = false;
        return $this->compiled;
    }
    
    /**
     * Add a source to our allow whitelist
     * 
     * @param string $dir
     * @param string $path
     */
    public function addSource($dir, $path)
    {
       if (!\preg_match('#\-src$#', $dir)) {
           $dir .= '-src';
       }
       $this->policies[$dir]['allow'][] = $path;
    }
    
    /**
     * Add a directive if it doesn't already exist
     * 
     * If it already exists, do nothing
     * 
     * @param string $key
     * @param mixed $value
     */
    public function addDirective($key, $value = null)
    {
        if ($value === null) {
            if (!isset($this->policies[$key])) {
                $this->policies[$key] = true;
            }
        } elseif (empty($this->policies[$key])) {
            $this->policies[$key] = $value;
        }
    }
    
    /**
     * Compile a subgroup into a policy string
     * 
     * @param string $directive
     * @param mixed $policies
     * 
     * @return string
     */
    protected function compileSubgroup($directive, $policies = null)
    {
        if ($policies === '*') {
            // Don't even waste the overhead adding this to the header
            return '';
        } elseif (empty($policies)) {
            return $directive.": 'none'; ";
        }
        $ret = $directive.': ';
        if (!empty($policies['self'])) {
            $ret .= "'self' ";
        }
        
        if (!empty($policies['allow'])) {
            foreach ($policies['allow'] as $url) {
                $url = \filter_var($url, FILTER_SANITIZE_URL);
                if ($url !== false) {
                    $ret .= $url.' ';
                }
            }
        }
        
        if (!empty($policies['hashes'])) {
            foreach ($policies['hashes'] as $hash) {
                foreach ($hash as $algo => $hashval) {
                    $ret .= \implode('', [
                        "'hash-",
                        \preg_replace('/[^A-Za-z0-9]/', '', $algo),
                        '-',
                        \preg_replace('/[^A-Za-z0-9_\+\.\/=]/', '', $hashval),
                        "' "
                    ]);
                }
            }
        }
        
        if (!empty($policies['nonces'])) {
            foreach ($policies['nonces'] as $nonce) {
                $ret .= \implode('', [
                    "'nonce-",
                    \preg_replace('/[^A-Za-z0-9_\+\.\/=]/', '', $nonce),
                    "' "
                ]);
            }
        }
        
        if (!empty($policies['unsafe-inline'])) {
            $ret .= "'unsafe-inline' ";
        }
        if (!empty($policies['unsafe-eval'])) {
            $ret .= "'unsafe-eval'";
        }
        return \rtrim($ret, ' ').'; ';
    }
    
    /**
     * Factory method - create a new CSPBuilder object from a JSON file
     * 
     * @param string $filename
     * @return CSPBuilder
     */
    public static function fromFile($filename = '')
    {
        if (!file_exists($filename)) {
            throw new \Exception($filename.' does not exist');
        }
        $json = \file_get_contents($filename);
        $array = \json_decode($json, true);
        return new CSPBuilder($array);
    }
    
    /**
     * Get the formatted CSP header 
     * 
     * @return string
     */
    public function getCompiledHeader()
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        return $this->compiled;
    }
    
    /**
     * 
     * Add a new nonce to the existing CSP
     * 
     * @param string $directive
     * @param string $script
     * @param string $algo
     * @return string
     */
    public function hash($directive = 'script-src', $script = '', $algo = 'sha256')
    {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array($directive, $ruleKeys)) {
            $hash = \base64_encode(\hash($algo, $script, true));
            $this->policies[$directive]['hashes'] []= [
                $algo => \strtr('+/', '-_', $hash)
            ];
        }
    }
    
    /**
     * Add a new nonce to the existing CSP
     * 
     * @param string $directive
     * @param string $nonce (if NULL, will be generated)
     */
    public function nonce($directive = 'script-src', $nonce = null)
    {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array($directive, $ruleKeys)) {
            if (empty($nonce)) {
                $nonce = \base64_encode(
                    \openssl_random_pseudo_bytes(18)
                );
            }
            $this->policies[$directive]['nonces'] []= $nonce;
            return $nonce;
        }
    }
    
    /**
     * Save CSP to a snippet file
     * 
     * @param string $outputFile Output file name
     * @param string $format Which format are we saving in?
     * @return int|boolean
     */
    public function saveSnippet($outputFile, $format = self::FORMAT_NGINX)
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        
        // Are we doing a report-only header?
        $which = $this->reportOnly 
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';
        
        switch ($format) {
            case self::FORMAT_NGINX:
                // In PHP < 7, implode() is faster than concatenation
                $output = \implode('', [
                    'add_header ',
                    $which,
                    ' "',
                        \rtrim($this->compiled, ' '),
                    '";',
                    "\n"
                ]);
                break;
            case self::FORMAT_APACHE:
                $output = \implode('', [
                    'Header add ',
                    $which,
                    ' "',
                        \rtrim($this->compiled, ' '),
                    '";',
                    "\n"
                ]);
                break;
            default:
                throw new \Exception('Unknown format: '.$format);
        }
        return \file_put_contents($outputFile, $output);
    }
    
    /**
     * Send the compiled CSP as a header()
     * 
     * @return boolean
     * @throws \Exception
     */
    public function sendCSPHeader()
    {
        if (\headers_sent()) {
            throw new \Exception('Headers already sent!');
        }
        if ($this->needsCompile) {
            $this->compile();
        }
        // Are we doing a report-only header?
        $which = $this->reportOnly 
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';
        
        \header($which.': '.$this->compiled);
    }
    
    /**
     * Set a directive
     * 
     * @param string $key
     * @param mixed $value
     */
    public function setDirective($key, $value = null)
    {
        $this->policies[$key] = $value;
    }
}
